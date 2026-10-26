"""Evaluate trusted CI applicability without executing repository expressions."""

import ast
import re

from core import require

UNKNOWN = object()


def pr_condition(expression, context=None):
    expression = expression.strip().removeprefix('${{').removesuffix('}}').strip()
    if not expression:
        return True
    if "''" in expression or '\\' in expression:
        return UNKNOWN
    text = re.sub(r'!(?!=)', ' not ', expression.replace('&&', ' and ').replace('||', ' or ')).strip()
    try:
        tree = ast.parse(text, mode='eval').body
    except (SyntaxError, ValueError):
        return UNKNOWN
    def read(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, (ast.Name, ast.Attribute)):
            name = ast.unparse(node)
            values = {'github.event_name': 'pull_request', 'github.event.pull_request.draft': False,
                      'true': True, 'false': False, **(context or {})}
            return values.get(name, UNKNOWN)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and not node.args and not node.keywords:
            return True if node.func.id in {'always', 'success'} else UNKNOWN
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            value = read(node.operand)
            return UNKNOWN if value is UNKNOWN else not value
        if isinstance(node, ast.BoolOp):
            values = [read(value) for value in node.values]
            if isinstance(node.op, ast.And):
                return False if any(v is False for v in values) else UNKNOWN if any(v is UNKNOWN for v in values) else all(values)
            return True if any(v is True for v in values) else UNKNOWN if any(v is UNKNOWN for v in values) else any(values)
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            left, right = read(node.left), read(node.comparators[0])
            if left is UNKNOWN or right is UNKNOWN:
                return UNKNOWN
            if isinstance(left, str) and isinstance(right, str):
                if left.isascii() and right.isascii():
                    left, right = left.lower(), right.lower()
                elif left != right:
                    return UNKNOWN
            elif type(left) is not type(right):
                return UNKNOWN
            if isinstance(node.ops[0], ast.Eq):
                return left == right
            if isinstance(node.ops[0], ast.NotEq):
                return left != right
        return UNKNOWN
    result = read(tree)
    return result if isinstance(result, bool) else UNKNOWN


def glob_matches(path, pattern):
    require(isinstance(pattern, str) and pattern and not any(c in pattern for c in '?+[]\\'),
            'ci_filter_configuration_required', str(pattern))
    result, index = '', 0
    while index < len(pattern):
        if pattern[index:index + 3] == '**/':
            result += '(?:.*/)?'
            index += 3
        elif pattern[index:index + 2] == '**':
            result += '.*'
            index += 2
        elif pattern[index] == '*':
            result += '[^/]*'
            index += 1
        else:
            result += re.escape(pattern[index])
            index += 1
    return re.fullmatch(result, path) is not None


def selected(path, patterns):
    match = False
    for pattern in patterns:
        negative = pattern.startswith('!')
        if glob_matches(path, pattern[1:] if negative else pattern):
            match = not negative
    return match


def applicable(check, branch, changed_paths):
    filters = check.get('filters', {})
    if filters.get('branches') and not selected(branch, filters['branches']):
        return False, 'The trusted workflow excludes this base branch.'
    if any(glob_matches(branch, p) for p in filters.get('branches-ignore', [])):
        return False, 'The trusted workflow ignores this base branch.'
    if filters.get('paths') and not any(selected(p, filters['paths']) for p in changed_paths):
        return False, 'No changed path matches the trusted workflow filters.'
    ignored = filters.get('paths-ignore', [])
    if ignored and changed_paths and all(any(glob_matches(p, pattern) for pattern in ignored) for p in changed_paths):
        return False, 'Every changed path is ignored by the trusted workflow.'
    return True, ''


def agent_authored(pr):
    branch = pr.get('head', {}).get('ref', '')
    author = pr.get('user', {}).get('login', '')
    return bool(re.match(r'^(?:agent|bot)/[^/]+/|^copilot/', branch) or author.endswith('[bot]'))
