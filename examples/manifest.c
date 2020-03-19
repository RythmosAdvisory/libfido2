/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/ec.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "../openbsd-compat/openbsd-compat.h"

#include "fido.h"

int
main(void)
{
	fido_dev_t		*dev;
	fido_dev_info_t		*devlist;
	size_t			 ndevs;
	int			 r;
	unsigned long long	 nok = 0;
	unsigned long long	 nfail = 0;

	fido_init(0);

	for (;;) {
		printf("looping: %llu/%llu\n", nfail, nok);

		if ((devlist = fido_dev_info_new(64)) == NULL)
			errx(1, "fido_dev_info_new");
		if ((dev = fido_dev_new()) == NULL)
			errx(1, "fido_dev_new");

		if ((r = fido_dev_info_manifest(devlist, 64, &ndevs)) != FIDO_OK)
			errx(1, "fido_dev_info_manifest: %s (0x%x)", fido_strerr(r), r);

		if (ndevs) {
			const fido_dev_info_t *di = fido_dev_info_ptr(devlist, 0);
			const char *path = fido_dev_info_path(di);
			const char *prod = fido_dev_info_product_string(di);
			printf("opening %s\n", prod);
			if ((r = fido_dev_open(dev, path)) != FIDO_OK) {
				nfail++;
				warn("fido_dev_open: %s", fido_strerr(r));
			} else {
				nok++;
				printf("ok\n");
				fido_dev_close(dev);
			}

		}

		fido_dev_info_free(&devlist, ndevs);
		fido_dev_free(&dev);
	}

	exit(0);
}
