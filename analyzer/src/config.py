import configparser
import os


def get_config(filename: str = "config.ini"):
    config_obj = configparser.ConfigParser(interpolation=None)
    config_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        filename,
    )
    config_obj.read(config_path)

    return config_obj


config = get_config()

integrations_config = get_config("integrations.ini")
