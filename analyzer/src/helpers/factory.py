import importlib
from config import config, integrations_config
import logging as logger

logger.getLogger(__name__)

STORAGE_ALIASES = {
    "s3": "storages.s3.S3Storage",
    "local": "storages.local.LocalStorage",
}

INTEGRATION_ALIASES = {
    "virustotal": "integrations.virustotal.VTLookup",
}


def get_storage_backend():
    storage_type = config.get("storage", "storage_type")

    metadata = dict(config["storage"])
    metadata.pop("storage_type")

    if storage_type not in STORAGE_ALIASES:
        raise ValueError(f"Unsupported storage type: {storage_type}")

    module_name, class_name = STORAGE_ALIASES[storage_type].rsplit(".", 1)
    module = importlib.import_module(module_name)
    storage_class = getattr(module, class_name)

    return storage_class(**metadata)


def get_integrations():
    found_integrations = []
    logger.info(f"Checking all configured intergations.")
    for integration_name in integrations_config.sections():
        logger.info(f"Enabling integration: {integration_name}")
        intg_config = dict(integrations_config[integration_name])
        if integration_name not in INTEGRATION_ALIASES:
            raise ValueError(f"Unsupported integration type: {integration_name}")

        if not intg_config.get("api_key"):
            continue

        module_name, class_name = INTEGRATION_ALIASES[integration_name].rsplit(".", 1)
        try:
            module = importlib.import_module(module_name)
            integration_class = getattr(module, class_name)
            found_integrations.append(
                {
                    "name": integration_name,
                    "class": integration_class(**intg_config),
                }
            )
        except Exception as e:
            logger.critical(
                f"Failed to load integration: {integration_name}. Error: {e}"
            )
            continue

        logger.info(
            f"Integration '{integration_name}' enabled for attachment analysis."
        )

    return found_integrations
