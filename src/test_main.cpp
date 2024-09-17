
#ifdef _WIN32
#include <Windows.h>
#endif // #ifdef _WIN32

#include "gtest/gtest.h"
#ifdef _WIN32
#include "ncrypt_cert_store_unittest.hpp"
#include "wincrypt_cert_store_unittest.hpp"
#else // #ifdef _WIN32
#include "asset_manager_unittest.hpp"
#include "tpm_wrapper_unittest.hpp"
#endif // #ifdef _WIN32
#include "apm_asset_processor_unittest.hpp"
#include "certificate_asset_processor_unittest.hpp"
#include "certificate_data_asset_processor_unittest.hpp"
#include "group_asset_processor_unittest.hpp"
#include "message_factory_unittest.hpp"
#include "rsa_utils_unittest.hpp"
#include "sat_asset_processor_unittest.hpp"
#include "script_asset_processor_unittest.hpp"
#include "script_utils_unittest.hpp"
#include "utils_unittest.hpp"

int main(int argc, char *argv[])
{
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
