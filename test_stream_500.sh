#!/usr/bin/env bash
# Reproduces Vertex AI 500 "Streaming is required" error.
# Sends a large tool-result payload with stream=false to the shim.
#
# Usage: ./test_stream_500.sh
#
# Reads port and auth token from ~/.claude/settings.json automatically.
# If the shim is forcing stream=true, this should succeed (SSE response).
# Without the fix, this returns a 500 error.

set -euo pipefail

SETTINGS="$HOME/.claude/settings.json"

if [ ! -f "$SETTINGS" ]; then
  echo "Error: $SETTINGS not found. Is the shim running?" >&2
  exit 1
fi

BASE_URL=$(python3 -c "import json; print(json.load(open('$SETTINGS'))['env']['ANTHROPIC_BASE_URL'])")
AUTH_TOKEN=$(python3 -c "import json; print(json.load(open('$SETTINGS'))['apiKeyHelper'].split()[-1])")

# Extract host:port from BASE_URL (e.g., http://127.0.0.1:8083/argoapi)
ENDPOINT="${BASE_URL%/argoapi}/v1/messages"

echo "Endpoint: $ENDPOINT"
echo "Generating large tool-result payload (~140KB, stream=false)..."

TMPFILE=$(mktemp /tmp/test_stream_500_XXXXXX.json)
trap "rm -f $TMPFILE" EXIT

python3 -c "
import json

lines = []
for i in range(500):
    lines.append(f'Line {i}: This is a detailed piece of content from a large document '
                 f'that contains technical information about software architecture, '
                 f'API design patterns, and system implementation details. It includes '
                 f'code examples, configuration snippets, and extensive documentation.')
content = '\n'.join(lines)

payload = {
    'model': 'claudeopus46',
    'max_tokens': 128000,
    'stream': False,
    'messages': [
        {'role': 'user', 'content': 'Read this large file and provide a comprehensive analysis.'},
        {'role': 'assistant', 'content': [
            {'type': 'text', 'text': \"I'll read the file for you.\"},
            {'type': 'tool_use', 'id': 'toolu_01XYZ789', 'name': 'Read',
             'input': {'file_path': '/tmp/large_file.txt'}}
        ]},
        {'role': 'user', 'content': [
            {'type': 'tool_result', 'tool_use_id': 'toolu_01XYZ789', 'content': content}
        ]}
    ],
    'tools': [{'name': 'Read', 'description': 'Read a file from disk',
               'input_schema': {'type': 'object',
                                'properties': {'file_path': {'type': 'string'}},
                                'required': ['file_path']}}]
}
with open('$TMPFILE', 'w') as f:
    json.dump(payload, f)
"

echo "Sending request..."
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "x-api-key: $AUTH_TOKEN" \
  -d @"$TMPFILE" 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')

if echo "$BODY" | head -c 200 | grep -q '"Streaming is required'; then
  echo "REPRODUCED: Got 500 'Streaming is required' error (no fix active)"
  echo "$BODY" | head -c 300
  echo ""
  exit 1
elif echo "$BODY" | head -c 50 | grep -q 'event: message_start'; then
  echo "OK: Shim forced stream=true, got SSE response (fix is active)"
  exit 0
else
  echo "UNEXPECTED (HTTP $HTTP_CODE):"
  echo "$BODY" | head -c 500
  echo ""
  exit 2
fi
