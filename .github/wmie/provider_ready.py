"""Read provider key policy before any inference starts."""
import json
import os
import urllib.request


def main():
    key = os.environ.get('WMIE_AGENT_OPENROUTER_API_KEY')
    if not key:
        raise SystemExit('The dedicated OpenRouter secret is missing. No AI analysis started.')
    request = urllib.request.Request('https://openrouter.ai/api/v1/key', headers={'Authorization': 'Bearer '+key})
    with urllib.request.urlopen(request, timeout=20) as response:
        data = json.load(response)['data']
    if data.get('limit') != 50 or data.get('limit_reset') != 'monthly':
        raise SystemExit('The dedicated key must use a 50 USD monthly limit. No AI analysis started.')
    if data.get('limit_remaining') is None or data['limit_remaining'] <= 0:
        raise SystemExit('The provider budget is exhausted or unknown. No AI analysis started.')
    print(json.dumps({'provider':'openrouter', 'monthly_limit_usd':50, 'state':'ready'}))


if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        raise SystemExit('Provider policy could not be read. No AI analysis started.')
