/*
 * Copyright (c) 2019 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
 */

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/entropy.h>
#include <mbedtls/entropy.h>
#include <entropy_poll.h>

psa_status_t zephyr_get_random(void *data,
			  unsigned char *output,
			  size_t len,
			  size_t *olen )

{
	const struct device *dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));
	uint16_t request_len = len > UINT16_MAX ? UINT16_MAX : len;
	int err;

	if (output == NULL || olen == NULL || len == 0) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	if (!device_is_ready(dev)) {
		return PSA_ERROR_HARDWARE_FAILURE;
	}

	err = entropy_get_entropy(dev, (uint8_t *)output, request_len);
	if (err < 0) {
		return PSA_ERROR_INSUFFICIENT_ENTROPY;
	}

	*olen = request_len;




    
    size_t chunk_size;

    (void)data;

    if (output == NULL || olen == NULL || len == 0) {
        return -1;
    }

    if (!device_is_ready(dev)) {
        return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }

    while (len > 0)
    {
        chunk_size = MIN(MBEDTLS_ENTROPY_MAX_GATHER, len);

        if (entropy_get_entropy(dev, output, chunk_size) < 0)
        {entropy_get_entropy
            return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        }

        *olen += chunk_size;
        output += chunk_size;
        len -= chunk_size;
    }

    return 0;
}
