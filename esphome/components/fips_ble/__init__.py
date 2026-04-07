import logging

import esphome.codegen as cg
from esphome.components.esp32 import add_idf_sdkconfig_option
import esphome.config_validation as cv
from esphome.const import CONF_ID

DEPENDENCIES = ["esp32"]
CODEOWNERS = ["@fips-ble"]

_LOGGER = logging.getLogger(__name__)

CONF_IDENTITY_SECRET = "identity_secret"
CONF_PEER_PUBLIC_KEY = "peer_public_key"
CONF_API_PORT = "api_port"

fips_ble_ns = cg.esphome_ns.namespace("fips_ble")

FipsBleComponent = fips_ble_ns.class_("FipsBleComponent", cg.Component)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(FipsBleComponent),
        cv.Required(CONF_IDENTITY_SECRET): cv.All(cv.string, cv.Length(min=64, max=64)),
        cv.Required(CONF_PEER_PUBLIC_KEY): cv.All(cv.string, cv.Length(min=66, max=66)),
        cv.Optional(CONF_API_PORT, default=6053): cv.port,
    }
).extend(cv.COMPONENT_SCHEMA)


def final_validation(config):
    add_idf_sdkconfig_option("CONFIG_BT_NIMBLE_ENABLED", True)
    add_idf_sdkconfig_option("CONFIG_BT_NIMBLE_L2CAP_COC_MAX_NUM", 1)
    add_idf_sdkconfig_option("CONFIG_BT_NIMBLE_GAP_DEVICE_NAME_MAX_LEN", 20)
    return config


FINAL_VALIDATE_SCHEMA = final_validation


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    cg.add(var.set_identity_secret(config[CONF_IDENTITY_SECRET]))
    cg.add(var.set_peer_public_key(config[CONF_PEER_PUBLIC_KEY]))
    cg.add(var.set_api_port(config[CONF_API_PORT]))

    cg.add_define("USE_FIPS_BLE")
