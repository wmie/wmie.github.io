"""Parse repository configuration as data. No constructors can execute code."""

from __future__ import annotations

import copy
from pathlib import Path
import re

from core import GovernanceError, require


def yaml_data(path):
    try:
        import yaml
    except ImportError as error:
        raise GovernanceError("yaml_parser_missing", "Install the pinned governance requirements.") from error

    class Loader(yaml.SafeLoader):
        pass

    # GitHub uses YAML 1.2 booleans. In YAML 1.1, the key `on` becomes True.
    Loader.yaml_implicit_resolvers = copy.deepcopy(Loader.yaml_implicit_resolvers)
    for key, values in Loader.yaml_implicit_resolvers.items():
        Loader.yaml_implicit_resolvers[key] = [item for item in values if item[0] != "tag:yaml.org,2002:bool"]
    Loader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"), list("tTfF"))
    path = Path(path)
    require(not path.is_symlink(), "yaml_symlink", str(path))
    require(path.stat().st_size <= 2 * 1024 * 1024, "yaml_too_large", str(path))
    try:
        data = yaml.load(path.read_text(), Loader=Loader)
        require(isinstance(data, dict), "yaml_object_required", str(path))
        return data
    except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
        raise GovernanceError("invalid_yaml", str(path)) from error
