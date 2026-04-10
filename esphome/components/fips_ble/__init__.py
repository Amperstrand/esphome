import hashlib
import logging

import esphome.codegen as cg
from esphome.components.esp32 import add_idf_sdkconfig_option, include_builtin_idf_component
import esphome.config_validation as cv
from esphome.const import CONF_ID
from esphome.core import CORE, HexInt

DEPENDENCIES = ["esp32"]
CODEOWNERS = ["@fips-ble"]

_LOGGER = logging.getLogger(__name__)

CONF_IDENTITY_SECRET = "identity_secret"
CONF_IDENTITY_SEED = "identity_seed"
CONF_PEER_PUBLIC_KEY = "peer_public_key"
CONF_PEER_MAC = "peer_mac"
CONF_API_PORT = "api_port"
CONF_SELFTEST = "selftest"

fips_ble_ns = cg.esphome_ns.namespace("fips_ble")

FipsBleComponent = fips_ble_ns.class_("FipsBleComponent", cg.Component)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(FipsBleComponent),
        cv.Optional(CONF_IDENTITY_SECRET): cv.All(cv.string, cv.Length(min=64, max=64)),
        cv.Optional(CONF_IDENTITY_SEED): cv.string_strict,
        cv.Required(CONF_PEER_PUBLIC_KEY): cv.All(cv.string, cv.Length(min=66, max=66)),
        cv.Optional(CONF_PEER_MAC): cv.mac_address,
        cv.Optional(CONF_API_PORT, default=6053): cv.port,
        cv.Optional(CONF_SELFTEST, default=False): cv.boolean,
    }
).extend(cv.COMPONENT_SCHEMA)


def final_validation(config):
    if CONF_IDENTITY_SECRET in config and CONF_IDENTITY_SEED in config:
        raise cv.Invalid(
            f"Only one of '{CONF_IDENTITY_SECRET}' or '{CONF_IDENTITY_SEED}' may be set"
        )
    add_idf_sdkconfig_option("CONFIG_BT_ENABLED", True)
    add_idf_sdkconfig_option("CONFIG_BT_BLE_ENABLED", True)
    add_idf_sdkconfig_option("CONFIG_BT_NIMBLE_ENABLED", True)
    add_idf_sdkconfig_option("CONFIG_BT_BLUEDROID_ENABLED", False)
    add_idf_sdkconfig_option("CONFIG_BT_CLASSIC_ENABLED", False)
    add_idf_sdkconfig_option("CONFIG_BT_NIMBLE_L2CAP_COC_MAX_NUM", 1)
    add_idf_sdkconfig_option("CONFIG_BT_NIMBLE_GAP_DEVICE_NAME_MAX_LEN", 20)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_HKDF_C", True)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_CHACHA20_C", True)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_POLY1305_C", True)
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_CHACHAPOLY_C", True)
    return config


FINAL_VALIDATE_SCHEMA = final_validation


def _derive_identity_secret(config):
    if CONF_IDENTITY_SECRET in config:
        return config[CONF_IDENTITY_SECRET].lower()

    seed = config.get(CONF_IDENTITY_SEED, CORE.name)
    material = f"esphome:fips_ble:{seed}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)

    cg.add(var.set_identity_secret(_derive_identity_secret(config)))
    cg.add(var.set_peer_public_key(config[CONF_PEER_PUBLIC_KEY]))
    if peer_mac := config.get(CONF_PEER_MAC):
        # NimBLE stores MAC in little-endian (wire) order: val[0] is LSB, val[5] is MSB.
        # cv.mac_address.parts gives human-readable big-endian order (MSB first), so reverse.
        cg.add(var.set_peer_mac([HexInt(part) for part in reversed(peer_mac.parts)]))
    cg.add(var.set_api_port(config[CONF_API_PORT]))
    cg.add(var.set_selftest(config[CONF_SELFTEST]))

    cg.add_build_flag("-DUSE_FIPS_BLE")
    include_builtin_idf_component("bt")
