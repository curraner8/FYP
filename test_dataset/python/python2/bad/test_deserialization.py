import pickle

import yaml


def load_user_data(serialized_data, yaml_config):
    # B3: Python Pickle is inherently unsafe
    user_obj = pickle.loads(serialized_data)

    # B5: Unsafe YAML loading (if the regex error is fixed)
    # This pattern matches your commented out Rule B5
    config = yaml.load(yaml_config)

    return user_obj, config
