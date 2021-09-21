/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2016-2020 Linaro LTD
 * Copyright (c) 2016-2019 JUUL Labs
 * Copyright (c) 2019-2021 Arm Limited
 *
 * Original license:
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/**
 * This file provides an interface to the boot loader.  Functions defined in
 * this file should only be called while the boot loader is running.
 */

#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <os/os_malloc.h>
#include "bootutil/bootutil.h"
#include "bootutil/image.h"
#include "bootutil_priv.h"
#include "swap_priv.h"
#include "bootutil/bootutil_log.h"
#include "bootutil/security_cnt.h"
#include "bootutil/boot_record.h"
#include "bootutil/fault_injection_hardening.h"
#include "bootutil/ramload.h"


#include "mcuboot_config/mcuboot_config.h"

#include <stdio.h>

MCUBOOT_LOG_MODULE_DECLARE(mcuboot);

static struct boot_loader_state boot_data;

#define IMAGES_ITER(x)

struct slot_usage_t {
    /* Index of the slot chosen to be loaded */
    uint32_t active_slot;
    bool slot_available[BOOT_NUM_SLOTS];
    /* Image destination and size for the active slot */
    uint64_t img_dst;
    uint32_t img_sz;
    /* Swap status for the active slot */
    struct boot_swap_state swap_state;
};

static int verbose = 0;

/*
 * This macro allows some control on the allocation of local variables.
 * When running natively on a target, we don't want to allocated huge
 * variables on the stack, so make them global instead. For the simulator
 * we want to run as many threads as there are tests, and it's safer
 * to just make those variables stack allocated.
 */
#if !defined(__BOOTSIM__)
#define TARGET_STATIC static
#else
#define TARGET_STATIC
#endif

static int
boot_read_image_headers(struct boot_loader_state *state, bool require_all,
        struct boot_status *bs)
{
    int rc;
    int i;

    for (i = 0; i < BOOT_NUM_SLOTS; i++) {
        rc = boot_read_image_header(state, i, boot_img_hdr(state, i), bs);
        if (rc != 0) {
            /* If `require_all` is set, fail on any single fail, otherwise
             * if at least the first slot's header was read successfully,
             * then the boot loader can attempt a boot.
             *
             * Failure to read any headers is a fatal error.
             */
            if (i > 0 && !require_all) {
                return 0;
            } else {
                return rc;
            }
        }
    }

    return 0;
}

/**
 * Fills rsp to indicate how booting should occur.
 *
 * @param  state        Boot loader status information.
 * @param  slot_usage   Information about the active and available slots.
 *                      Only used in MCUBOOT_DIRECT_XIP and MCUBOOT_RAM_LOAD
 * @param  rsp          boot_rsp struct to fill.
 */
static void
fill_rsp(struct boot_loader_state *state, void *slot_usage,
         struct boot_rsp *rsp)
{
    uint32_t active_slot;


    active_slot = ((struct slot_usage_t *)slot_usage)[BOOT_CURR_IMG(state)].active_slot;

    rsp->br_flash_dev_id = BOOT_IMG_AREA(state, active_slot)->fa_device_id;
    rsp->br_image_off = boot_img_slot_off(state, active_slot);
    rsp->br_hdr = boot_img_hdr(state, active_slot);
}

/**
 * Closes all flash areas.
 *
 * @param  state    Boot loader status information.
 */
static void
close_all_flash_areas(struct boot_loader_state *state)
{
    uint32_t slot;

    IMAGES_ITER(BOOT_CURR_IMG(state)) {
#if MCUBOOT_SWAP_USING_SCRATCH
        flash_area_close(BOOT_SCRATCH_AREA(state));
#endif
        for (slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
            flash_area_close(BOOT_IMG_AREA(state, BOOT_NUM_SLOTS - 1 - slot));
        }
    }
}

/*
 * Compute the total size of the given image.  Includes the size of
 * the TLVs.
 */
#if !defined(MCUBOOT_OVERWRITE_ONLY) ||  defined(MCUBOOT_OVERWRITE_ONLY_FAST)
static int
boot_read_image_size(struct boot_loader_state *state, int slot, uint32_t *size)
{
    const struct flash_area *fap;
    struct image_tlv_info info;
    uint32_t off;
    uint32_t protect_tlv_size;
    int area_id;
    int rc;

    (void)state;

    area_id = flash_area_id_from_multi_image_slot(BOOT_CURR_IMG(state), slot);
    rc = flash_area_open(area_id, &fap);
    if (rc != 0) {
        rc = BOOT_EFLASH;
        goto done;
    }

    off = BOOT_TLV_OFF(boot_img_hdr(state, slot));

    if (flash_area_read(fap, off, &info, sizeof(info))) {
        rc = BOOT_EFLASH;
        goto done;
    }

    protect_tlv_size = boot_img_hdr(state, slot)->ih_protect_tlv_size;
    if (info.it_magic == IMAGE_TLV_PROT_INFO_MAGIC) {
        if (protect_tlv_size != info.it_tlv_tot) {
            rc = BOOT_EBADIMAGE;
            goto done;
        }

        if (flash_area_read(fap, off + info.it_tlv_tot, &info, sizeof(info))) {
            rc = BOOT_EFLASH;
            goto done;
        }
    } else if (protect_tlv_size != 0) {
        rc = BOOT_EBADIMAGE;
        goto done;
    }

    if (info.it_magic != IMAGE_TLV_INFO_MAGIC) {
        rc = BOOT_EBADIMAGE;
        goto done;
    }

    *size = off + protect_tlv_size + info.it_tlv_tot;
    rc = 0;

done:
    flash_area_close(fap);
    return rc;
}
#endif /* !MCUBOOT_OVERWRITE_ONLY */


/*
 * Validate image hash/signature and optionally the security counter in a slot.
 */
static fih_int
boot_image_check(struct boot_loader_state *state, struct image_header *hdr,
                 const struct flash_area *fap, struct boot_status *bs)
{
    TARGET_STATIC uint8_t tmpbuf[BOOT_TMPBUF_SZ];
    uint8_t image_index;
    int rc;
    fih_int fih_rc = FIH_FAILURE;

    (void)state;

    (void)bs;
    (void)rc;

    image_index = BOOT_CURR_IMG(state);


    FIH_CALL(bootutil_img_validate, fih_rc, BOOT_CURR_ENC(state), image_index,
             hdr, fap, tmpbuf, BOOT_TMPBUF_SZ, NULL, 0, NULL);

    FIH_RET(fih_rc);
}


/*
 * Check that this is a valid header.  Valid means that the magic is
 * correct, and that the sizes/offsets are "sane".  Sane means that
 * there is no overflow on the arithmetic, and that the result fits
 * within the flash area we are in.
 */
static bool
boot_is_header_valid(const struct image_header *hdr, const struct flash_area *fap)
{
    uint32_t size;

    if (hdr->ih_magic != IMAGE_MAGIC) {
        return false;
    }

    if (!boot_u32_safe_add(&size, hdr->ih_img_size, hdr->ih_hdr_size)) {
        return false;
    }

    if (size >= fap->fa_size) {
        return false;
    }

    return true;
}

/*
 * Check that a memory area consists of a given value.
 */
static inline bool
boot_data_is_set_to(uint8_t val, void *data, size_t len)
{
    uint8_t i;
    uint8_t *p = (uint8_t *)data;
    for (i = 0; i < len; i++) {
        if (val != p[i]) {
            return false;
        }
    }
    return true;
}

static int
boot_check_header_erased(struct boot_loader_state *state, int slot)
{
    const struct flash_area *fap;
    struct image_header *hdr;
    uint8_t erased_val;
    int area_id;
    int rc;

    area_id = flash_area_id_from_multi_image_slot(BOOT_CURR_IMG(state), slot);
    rc = flash_area_open(area_id, &fap);
    if (rc != 0) {
        return -1;
    }

    erased_val = flash_area_erased_val(fap);
    flash_area_close(fap);

    hdr = boot_img_hdr(state, slot);
    if (!boot_data_is_set_to(erased_val, &hdr->ih_magic, sizeof(hdr->ih_magic))) {
        return -1;
    }

    return 0;
}

#if (BOOT_IMAGE_NUMBER > 1) || \
    defined(MCUBOOT_DIRECT_XIP) || \
    defined(MCUBOOT_RAM_LOAD) || \
    (defined(MCUBOOT_OVERWRITE_ONLY) && defined(MCUBOOT_DOWNGRADE_PREVENTION))
/**
 * Compare image version numbers not including the build number
 *
 * @param ver1           Pointer to the first image version to compare.
 * @param ver2           Pointer to the second image version to compare.
 *
 * @retval -1           If ver1 is strictly less than ver2.
 * @retval 0            If the image version numbers are equal,
 *                      (not including the build number).
 * @retval 1            If ver1 is strictly greater than ver2.
 */
static int
boot_version_cmp(const struct image_version *ver1,
                 const struct image_version *ver2)
{
    if (ver1->iv_major > ver2->iv_major) {
        return 1;
    }
    if (ver1->iv_major < ver2->iv_major) {
        return -1;
    }
    /* The major version numbers are equal, continue comparison. */
    if (ver1->iv_minor > ver2->iv_minor) {
        return 1;
    }
    if (ver1->iv_minor < ver2->iv_minor) {
        return -1;
    }
    /* The minor version numbers are equal, continue comparison. */
    if (ver1->iv_revision > ver2->iv_revision) {
        return 1;
    }
    if (ver1->iv_revision < ver2->iv_revision) {
        return -1;
    }

    /* The revision numbers are equal, continue comparison. */
    if (ver1->iv_build_num > ver2->iv_build_num) {
        return 1;
    }
    if (ver1->iv_build_num < ver2->iv_build_num) {
        return -1;
    }
    return 0;
}
#endif


/*
 * Check that there is a valid image in a slot
 *
 * @returns
 *         FIH_SUCCESS                      if image was successfully validated
 *         1 (or its fih_int encoded form)  if no bootloable image was found
 *         FIH_FAILURE                      on any errors
 */
static fih_int
boot_validate_slot(struct boot_loader_state *state, int slot,
                   struct boot_status *bs)
{
    const struct flash_area *fap;
    struct image_header *hdr;
    int area_id;
    fih_int fih_rc = FIH_FAILURE;
    int rc;

    area_id = flash_area_id_from_multi_image_slot(BOOT_CURR_IMG(state), slot);
    rc = flash_area_open(area_id, &fap);
    if (rc != 0) {
        BOOT_LOG_ERR("%s: flash_area_open failed", __FUNCTION__);
        FIH_RET(fih_rc);
    }

    hdr = boot_img_hdr(state, slot);

    if (boot_check_header_erased(state, slot) == 0 ||
        (hdr->ih_flags & IMAGE_F_NON_BOOTABLE)) {

        /* No bootable image in slot; continue booting from the primary slot. */
        fih_rc = fih_int_encode(1);
        goto out;
    }

#if defined(MCUBOOT_OVERWRITE_ONLY) && defined(MCUBOOT_DOWNGRADE_PREVENTION)
    if (slot != BOOT_PRIMARY_SLOT) {
        /* Check if version of secondary slot is sufficient */
        rc = boot_version_cmp(
                &boot_img_hdr(state, BOOT_SECONDARY_SLOT)->ih_ver,
                &boot_img_hdr(state, BOOT_PRIMARY_SLOT)->ih_ver);
        if (rc < 0 && boot_check_header_erased(state, BOOT_PRIMARY_SLOT)) {
            BOOT_LOG_ERR("insufficient version in secondary slot");
            flash_area_erase(fap, 0, fap->fa_size);
            /* Image in the secondary slot does not satisfy version requirement.
             * Erase the image and continue booting from the primary slot.
             */
            fih_rc = fih_int_encode(1);
            goto out;
        }
    }
#endif

    FIH_CALL(boot_image_check, fih_rc, state, hdr, fap, bs);
    if (!boot_is_header_valid(hdr, fap) || fih_not_eq(fih_rc, FIH_SUCCESS)) {
        if ((slot != BOOT_PRIMARY_SLOT) || ARE_SLOTS_EQUIVALENT()) {
            flash_area_erase(fap, 0, fap->fa_size);
            /* Image is invalid, erase it to prevent further unnecessary
             * attempts to validate and boot it.
             */
        }
#if !defined(__BOOTSIM__)
        BOOT_LOG_ERR("Image in the %s slot is not valid!",
                     (slot == BOOT_PRIMARY_SLOT) ? "primary" : "secondary");
#endif
        fih_rc = fih_int_encode(1);
        goto out;
    }

out:
    flash_area_close(fap);

    FIH_RET(fih_rc);
}



#define NO_ACTIVE_SLOT UINT32_MAX

/**
 * Opens all flash areas and checks which contain an image with a valid header.
 *
 * @param  state        Boot loader status information.
 * @param  slot_usage   Structure to fill with information about the available
 *                      slots.
 *
 * @return              0 on success; nonzero on failure.
 */
static int
boot_get_slot_usage(struct boot_loader_state *state,
                    struct slot_usage_t slot_usage[])
{
    uint32_t slot;
    int fa_id;
    int rc;
    struct image_header *hdr = NULL;

    IMAGES_ITER(BOOT_CURR_IMG(state)) {
        /* Open all the slots */
        for (slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
            fa_id = flash_area_id_from_multi_image_slot(
                                                BOOT_CURR_IMG(state), slot);
            rc = flash_area_open(fa_id, &BOOT_IMG_AREA(state, slot));
            assert(rc == 0);
        }

        /* Attempt to read an image header from each slot. */
        rc = boot_read_image_headers(state, false, NULL);
        if (rc != 0) {
            BOOT_LOG_WRN("Failed reading image headers.");
            return rc;
        }

        /* Check headers in all slots */
        for (slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
            hdr = boot_img_hdr(state, slot);

            if (boot_is_header_valid(hdr, BOOT_IMG_AREA(state, slot))) {
                slot_usage[BOOT_CURR_IMG(state)].slot_available[slot] = true;
                BOOT_LOG_IMAGE_INFO(slot, hdr);
            } else {
                slot_usage[BOOT_CURR_IMG(state)].slot_available[slot] = false;
            }
        }

        slot_usage[BOOT_CURR_IMG(state)].active_slot = NO_ACTIVE_SLOT;
    }

    return 0;
}

/**
 * Finds the slot containing the image with the highest version number for the
 * current image.
 *
 * @param  state        Boot loader status information.
 * @param  slot_usage   Information about the active and available slots.
 *
 * @return              NO_ACTIVE_SLOT if no available slot found, number of
 *                      the found slot otherwise.
 */
static char *boot_strs[] = {
"Zero",
"Set", //       1
"Bad", //       2
"Unset", //     3
"Any", //       4 
};

static char *swap_strs[] = {
"Zero",
"None", //     1
"Test", //     2
"Perm", //     3
"Revert", //   4
"Fail", //     5
};
struct boot_swap_state myswap[2];

static char *area_strs[] = {
    "BOOT_AREA!!",
    "PRIMARY  ",
    "SECONDARY",
    "GARBAGE  ",
};
#define FLASH_AREA_PRIMARY      1
#define FLASH_AREA_SECONDARY    2

static void
dump_swap(int area)
{
    struct boot_swap_state state;
    int rc;
    
    /* id == indicates which partition in dts file */
    /* Assumes single IMAGE ... e.g. single image with primary and secondary slots */

    area &= 0x3;

    rc = boot_read_swap_state_by_id(area, &state);
    if (!rc)
        printf("%s  : magic: %s, swap_type: %s, copy_done: %s, image_ok: %s\n", area_strs[area],
            boot_strs[state.magic], swap_strs[state.swap_type], boot_strs[state.copy_done], boot_strs[state.image_ok]);
    else
        printf("%s: Couldn't read area %d!\n", __FUNCTION__, area);
}

#define USE_VERSION
#ifdef USE_VERSION
static uint32_t
find_slot_with_highest_version(struct boot_loader_state *state,
                               struct slot_usage_t slot_usage[])
{
    uint32_t slot;
    uint32_t candidate_slot = NO_ACTIVE_SLOT;
    int rc;

    for (slot = 0; slot < BOOT_NUM_SLOTS; slot++) {
        if (slot_usage[BOOT_CURR_IMG(state)].slot_available[slot]) {
            if (candidate_slot == NO_ACTIVE_SLOT) {
                candidate_slot = slot;
            } else {
                rc = boot_version_cmp(
                            &boot_img_hdr(state, slot)->ih_ver,
                            &boot_img_hdr(state, candidate_slot)->ih_ver);
                if (rc == 1) {
                    /* The version of the image being examined is greater than
                     * the version of the current candidate.
                     */
                    candidate_slot = slot;
                }
            }
        }
    }

    BOOT_LOG_INF("Highest version (%u.%u.%u+%u) is in %s slot",
        boot_img_hdr(state, candidate_slot)->ih_ver.iv_major,
        boot_img_hdr(state, candidate_slot)->ih_ver.iv_minor,
        boot_img_hdr(state, candidate_slot)->ih_ver.iv_revision,
        boot_img_hdr(state, candidate_slot)->ih_ver.iv_build_num,
        (candidate_slot == BOOT_PRIMARY_SLOT) ? "PRIMARY" : "SECONDARY");

    return candidate_slot;
}
#else /* Below is !USE_VERSION */
static uint32_t
find_slot_scorpio(struct boot_loader_state *state,
                              struct slot_usage_t slot_usage[])
{
    int myslot;
    int score[2];

    printf("Using SCORPIO algorithm to choose boot slot\n");
    /* 
     * get swap states for each slot
     */
    for (myslot = 0; myslot < 2; myslot++)
    {
        const struct flash_area *fap;
        int fa_id;
        int rc;

        fa_id = flash_area_id_from_multi_image_slot(BOOT_CURR_IMG(state), myslot);
        rc = flash_area_open(fa_id, &fap);
        assert(rc == 0);

        memset(&myswap[myslot], 0, sizeof(struct boot_swap_state));
        rc = boot_read_swap_state(fap, &myswap[myslot]);
        assert(rc == 0);
        flash_area_close(fap);

        score[myslot] = 0;
    }

    /*
     * Experiment with creating score for each slot
     */
    for (myslot = 0; myslot < 2; myslot++)
    {
        if (slot_usage[BOOT_CURR_IMG(state)].slot_available[myslot] == true)
        {
            if (verbose)
            {
                printf("%s: Slot %d: magic: %s, swap_type %s, copy_done: %s, image_ok: %s\n", __FUNCTION__, myslot,
                    boot_strs[myswap[myslot].magic],
                    swap_strs[myswap[myslot].swap_type],
                    boot_strs[myswap[myslot].copy_done],
                    boot_strs[myswap[myslot].image_ok]);
            }

            if (myswap[myslot].magic == BOOT_FLAG_SET) {
                score[myslot]++;
            }
            if (myswap[myslot].image_ok == BOOT_FLAG_SET)
            {
                score[myslot]++;
            }
        }
    }

    /*
     * No slot is available
     */
    if (!score[0] && !score[1]) {
        printf("%s: Scorpio algo: No Slots available!!\n", __FUNCTION__);
        return NO_ACTIVE_SLOT;
    }

    /*
     * Slot has good Magic and  swap indicates it wants to run.
     * #define BOOT_PRIMARY_SLOT               0
     * #define BOOT_SECONDARY_SLOT             1
     *
     * Try secondary first...
     */
    for (myslot = BOOT_SECONDARY_SLOT; myslot >= BOOT_PRIMARY_SLOT; myslot--)
    {
        if (slot_usage[BOOT_CURR_IMG(state)].slot_available[myslot] &&
           (myswap[myslot].magic == BOOT_FLAG_SET) && 
           ((myswap[myslot].swap_type == BOOT_SWAP_TYPE_PERM) || (myswap[myslot].swap_type == BOOT_SWAP_TYPE_TEST)))
        {
            printf("%s: Scorpio algo: SWAP Requested: Selecting %s slot to boot\n", __FUNCTION__, myslot == BOOT_SECONDARY_SLOT ? "SECONDARY" : "PRIMARY");
            return(myslot);
        }
    }

    /*
     * Still here? Return highest score
     */
    printf("%s: Scorpio algo: High Score: Selecting %s slot to boot\n", __FUNCTION__, myslot == BOOT_SECONDARY_SLOT ? "SECONDARY" : "PRIMARY");
    return score[0] > score[1] ? 0 : 1; 

}
#endif /* USE_VERSION */


#ifdef MCUBOOT_HAVE_LOGGING
/**
 * Prints the state of the loaded images.
 *
 * @param  state        Boot loader status information.
 * @param  slot_usage   Information about the active and available slots.
 */
static void
print_loaded_images(struct boot_loader_state *state,
                    struct slot_usage_t slot_usage[])
{
    uint32_t active_slot;

    return;

    IMAGES_ITER(BOOT_CURR_IMG(state)) {
        active_slot = slot_usage[BOOT_CURR_IMG(state)].active_slot;

        BOOT_LOG_INF("Image %d loaded from the %s slot",
                     BOOT_CURR_IMG(state),
                     (active_slot == BOOT_PRIMARY_SLOT) ?
                     "primary" : "secondary");
    }
}
#endif

//#ifdef MCUBOOT_DIRECT_XIP_REVERT
/**
 * Checks whether the active slot of the current image was previously selected
 * to run. Erases the image if it was selected but its execution failed,
 * otherwise marks it as selected if it has not been before.
 *
 * @param  state        Boot loader status information.
 * @param  slot_usage   Information about the active and available slots.
 *
 * @return              0 on success; nonzero on failure.
 */
static int
boot_select_or_erase(struct boot_loader_state *state,
                     struct slot_usage_t slot_usage[])
{
    const struct flash_area *fap;
    int fa_id;
    int rc;
    uint32_t active_slot;
    struct boot_swap_state* active_swap_state;

    active_slot = slot_usage[BOOT_CURR_IMG(state)].active_slot;

    fa_id = flash_area_id_from_multi_image_slot(BOOT_CURR_IMG(state), active_slot);
    rc = flash_area_open(fa_id, &fap);
    assert(rc == 0);

    active_swap_state = &(slot_usage[BOOT_CURR_IMG(state)].swap_state);

    memset(active_swap_state, 0, sizeof(struct boot_swap_state));
    rc = boot_read_swap_state(fap, active_swap_state);
    assert(rc == 0);

    /* if (magic is bad || (copy_done && !image_ok && swapping))
     * We are trying new image, copy_done indicates this images was booted but it
     * didn;t get confirmed.
     * So this image was booted but didn't get confirmed...yank it.
     * */

    if ((active_swap_state->magic != BOOT_MAGIC_GOOD) ||
        ((active_swap_state->copy_done == BOOT_FLAG_SET) &&
         (active_swap_state->image_ok  != BOOT_FLAG_SET)))
    {
        /*
         * A reboot happened without the image being confirmed at
         * runtime or its trailer is corrupted/invalid. Erase the image
         * to prevent it from being selected again on the next reboot.
         */ 
        printf("*\n* %s Slot booted with no confirmation or is corrupt.\n", active_slot == BOOT_PRIMARY_SLOT ? "Primary" : "Secondary");
        printf("* ERASING %s\n*\n", active_slot == BOOT_PRIMARY_SLOT ? "Primary" : "Secondary");
            rc = flash_area_erase(fap, 0, fap->fa_size);
            assert(rc == 0);
            rc = -1;

        flash_area_close(fap);

    } else {
        if (active_swap_state->copy_done != BOOT_FLAG_SET) {
            if (verbose)
            {
                printf("%s: Set copy_done in active slot.\n", __FUNCTION__);
            }
            if (active_swap_state->copy_done == BOOT_FLAG_BAD) {
                printf("FYI: The copy_done flag had an unexpected value. Its "
                             "value was neither 'set' nor 'unset', but 'bad'.\n");
            }
            /*
             * Set the copy_done flag, indicating that the image has been
             * selected to boot. It can be set in advance, before even
             * validating the image, because in case the validation fails, the
             * entire image slot will be erased (including the trailer).
             */
            rc = boot_write_copy_done(fap);
            if (rc != 0) {
                printf("Failed to set copy_done flag\n");
                rc = 0;
            }
        }
        flash_area_close(fap);

        /* XXX Need to clear copy_done on the other slot! */
        /* Once we can do this, mcuboot_shell can detemrine which slot was booted, so when we confirm, teach it
         * to confirm whichever slot was booted.
         */
        {
            int passive_slot = BOOT_SECONDARY_SLOT - active_slot;
            uint8_t erased_val;

            if (slot_usage[BOOT_CURR_IMG(state)].slot_available[passive_slot])
            {
                if (verbose)
                    printf("%s, Booted from %s, clear copy_done on other slot %s\n",
                        __FUNCTION__,
                        active_slot == BOOT_PRIMARY_SLOT ? "Primary" : "Secondary",
                        passive_slot == BOOT_PRIMARY_SLOT ? "Primary" : "Secondary");

                fa_id = flash_area_id_from_multi_image_slot(BOOT_CURR_IMG(state), passive_slot);
                rc = flash_area_open(fa_id, &fap);
                erased_val = flash_area_erased_val(fap);
                boot_write_copy_done_with_flag(fap, erased_val);
                flash_area_close(fap);
            } else {
                if (verbose)
                    printf("%s: Other slot (%s) doesn't exist, no copy_done to clear.\n",
                        __FUNCTION__, passive_slot == BOOT_PRIMARY_SLOT ? "Primary" : "Secondary");
            }
        }
    }

    return rc;
}
//#endif /* MCUBOOT_DIRECT_XIP_REVERT */


#ifndef MULTIPLE_EXECUTABLE_RAM_REGIONS
#if !defined(IMAGE_EXECUTABLE_RAM_START) || !defined(IMAGE_EXECUTABLE_RAM_SIZE)
#error "Platform MUST define executable RAM bounds in case of RAM_LOAD"
#endif
#endif

/**
 * Verifies that the active slot of the current image can be loaded within the
 * predefined bounds that are allowed to be used by executable images.
 *
 * @param  state        Boot loader status information.
 * @param  slot_usage   Information about the active and available slots.
 *
 * @return              0 on success; nonzero on failure.
 */
static int
boot_verify_ram_load_address(struct boot_loader_state *state,
                             struct slot_usage_t slot_usage[])
{
    uint64_t img_dst;
    uint32_t img_sz;
    uint32_t img_end_addr;
    uint64_t exec_ram_start;
    uint32_t exec_ram_size;
#ifdef MULTIPLE_EXECUTABLE_RAM_REGIONS
    int      rc;

    rc = boot_get_image_exec_ram_info(BOOT_CURR_IMG(state), &exec_ram_start,
                                      &exec_ram_size);
    if (rc != 0) {
        return BOOT_EBADSTATUS;
    }
#else
    exec_ram_start = (uint64_t)IMAGE_EXECUTABLE_RAM_START;
    exec_ram_size = IMAGE_EXECUTABLE_RAM_SIZE;
#endif

    img_dst = slot_usage[BOOT_CURR_IMG(state)].img_dst;
    img_sz = slot_usage[BOOT_CURR_IMG(state)].img_sz;

    if (img_dst < exec_ram_start) {
        return BOOT_EBADIMAGE;
    }

    if (!boot_u32_safe_add(&img_end_addr, img_dst, img_sz)) {
        return BOOT_EBADIMAGE;
    }

    if (img_end_addr > (exec_ram_start + exec_ram_size)) {
        return BOOT_EBADIMAGE;
    }

    return 0;
}

/**
 * Copies a slot of the current image into SRAM.
 *
 * @param  state    Boot loader status information.
 * @param  slot     The flash slot of the image to be copied to SRAM.
 * @param  img_dst  The address at which the image needs to be copied to
 *                  SRAM.
 * @param  img_sz   The size of the image that needs to be copied to SRAM.
 *
 * @return          0 on success; nonzero on failure.
 */
static int
boot_copy_image_to_sram(struct boot_loader_state *state, int slot,
                        uint64_t img_dst, uint32_t img_sz)
{
    int rc;
    const struct flash_area *fap_src = NULL;
    int area_id;

    (void)state;

    area_id = flash_area_id_from_multi_image_slot(BOOT_CURR_IMG(state), slot);

    rc = flash_area_open(area_id, &fap_src);
    if (rc != 0) {
        return BOOT_EFLASH;
    }

    /*
     * Scorpio flash driver only handles a single sector at a time.
     * TODO: Let scorpio handle infinite length.
     */
#define SCORP_SECTOR_SZ 512

#ifdef CONFIG_SCORPIO_BOOTLOADER
    /* Direct copy from flash to its new location in SRAM. */
    BOOT_LOG_INF("Copying image from %s slot into LPDDR", slot ? "SECONDARY" : "PRIMARY");
    //BOOT_LOG_INF("  image size  = %d", img_sz);
    //BOOT_LOG_INF("  destination = 0x%llx", img_dst);
    
    int local_offset = 0;
    while (img_sz > 0) {
        int sz = MIN(SCORP_SECTOR_SZ, img_sz);
        rc = flash_area_read(fap_src, local_offset, (void *)(uint64_t)(img_dst + local_offset), sz);
        if (rc != 0) {
            BOOT_LOG_INF("Error whilst copying image from Flash to SRAM: %d", rc);
        }
        img_sz -= sz;
        local_offset += sz;
    }
#endif // CONFIG_SCORPIO_BOOTLOADER

    flash_area_close(fap_src);

    return rc;
}


/**
 * Loads the active slot of the current image into SRAM. The load address and
 * image size is extracted from the image header.
 *
 * @param  state        Boot loader status information.
 * @param  slot_usage   Information about the active and available slots.
 *
 * @return              0 on success; nonzero on failure.
 */
static int
boot_load_image_to_sram(struct boot_loader_state *state,
                        struct slot_usage_t slot_usage[])
{
    uint32_t active_slot;
    struct image_header *hdr = NULL;
    uint64_t img_dst;
    uint32_t img_sz;
    int rc;

    active_slot = slot_usage[BOOT_CURR_IMG(state)].active_slot;
    hdr = boot_img_hdr(state, active_slot);

    if (hdr->ih_flags & IMAGE_F_RAM_LOAD) {

        img_dst = hdr->ih_load_addr;

        rc = boot_read_image_size(state, active_slot, &img_sz);
        if (rc != 0) {
            return rc;
        }

        slot_usage[BOOT_CURR_IMG(state)].img_dst = img_dst;
        slot_usage[BOOT_CURR_IMG(state)].img_sz = img_sz;

        rc = boot_verify_ram_load_address(state, slot_usage);
        if (rc != 0) {
            BOOT_LOG_INF("Image RAM load address 0x%llx is invalid.", img_dst);
            return rc;
        }


        /* Copy image to the load address from where it currently resides in
         * flash.
         */
        rc = boot_copy_image_to_sram(state, active_slot, img_dst, img_sz);
        if (rc != 0) 
        {
            BOOT_LOG_ERR("RAM loading to 0x%llx is failed.", img_dst);
        }
    } else {
        /* Only images that support IMAGE_F_RAM_LOAD are allowed if
         * MCUBOOT_RAM_LOAD is set.
         */
        rc = BOOT_EBADIMAGE;
    }

    if (rc != 0) {
        slot_usage[BOOT_CURR_IMG(state)].img_dst = 0;
        slot_usage[BOOT_CURR_IMG(state)].img_sz = 0;
    }

    return rc;
}

/**
 * Removes an image from SRAM, by overwriting it with zeros.
 *
 * @param  state        Boot loader status information.
 * @param  slot_usage   Information about the active and available slots.
 *
 * @return              0 on success; nonzero on failure.
 */
static inline int
boot_remove_image_from_sram(struct boot_loader_state *state,
                            struct slot_usage_t slot_usage[])
{
    BOOT_LOG_INF("Removing image from SRAM at address 0x%p",
                 (void*)slot_usage[BOOT_CURR_IMG(state)].img_dst);

    memset((void*)slot_usage[BOOT_CURR_IMG(state)].img_dst, 0,
           slot_usage[BOOT_CURR_IMG(state)].img_sz);

    slot_usage[BOOT_CURR_IMG(state)].img_dst = 0;
    slot_usage[BOOT_CURR_IMG(state)].img_sz = 0;

    return 0;
}

/**
 * Removes an image from flash by erasing the corresponding flash area
 *
 * @param  state    Boot loader status information.
 * @param  slot     The flash slot of the image to be erased.
 *
 * @return          0 on success; nonzero on failure.
 */
static inline int
boot_remove_image_from_flash(struct boot_loader_state *state, uint32_t slot)
{
    int area_id;
    int rc;
    const struct flash_area *fap;

    BOOT_LOG_INF("Removing image %d slot %d from flash", BOOT_CURR_IMG(state),
                                                         slot);
    area_id = flash_area_id_from_multi_image_slot(BOOT_CURR_IMG(state), slot);
    rc = flash_area_open(area_id, &fap);
    if (rc == 0) {
        flash_area_erase(fap, 0, fap->fa_size);
    }

    return rc;
}

/**
 * Tries to load a slot for all the images with validation.
 *
 * @param  state        Boot loader status information.
 * @param  slot_usage   Information about the active and available slots.
 *
 * @return              0 on success; nonzero on failure.
 */
fih_int
boot_load_and_validate_images(struct boot_loader_state *state,
                              struct slot_usage_t slot_usage[])
{
    uint32_t active_slot;
    int rc;
    fih_int fih_rc;

    /* Go over all the images and try to load one */
    IMAGES_ITER(BOOT_CURR_IMG(state)) {
        /* All slots tried until a valid image found. Breaking from this loop
         * means that a valid image found or already loaded. If no slot is
         * found the function returns with error code. */
        while (true) {

            /* 
             * Just starting, so active_slot shouldn't be selected yet.
             * (If multiple images, maybe a different story).
             */
            active_slot = slot_usage[BOOT_CURR_IMG(state)].active_slot;
            if (active_slot != NO_ACTIVE_SLOT){
                /* A slot is already active, go to next image. */
                break;
            }

            /* 
             * Loop thru avail_slots, find highest version number
             */
#ifdef USE_VERSION
            active_slot = find_slot_with_highest_version(state,
                                                         slot_usage);
#else
            /* choose based on flags */
            active_slot = find_slot_scorpio(state, slot_usage);

#endif

            if (active_slot == NO_ACTIVE_SLOT) {
                printf("%s: No good slot\n", __FUNCTION__);
                BOOT_LOG_INF("No slot to load for image %d",
                             BOOT_CURR_IMG(state));
                FIH_RET(FIH_FAILURE);
            }

            /*
             * Active slot is now chosen
             */
            slot_usage[BOOT_CURR_IMG(state)].active_slot = active_slot;

            if (verbose)
            {
                printf("%s: Set Active slot %d/%s\n",
                    __FUNCTION__, active_slot, active_slot == BOOT_PRIMARY_SLOT ? "Primary" : "Secondary");
            }

            /* 
             * Checks whether the active slot was previously selected to run. 
             * If it was selected but its execution failed => erase image.
             * Otherwise set its swap flags appropriately.
             *
             * Active slot remains unchanged at highest version.
             */
            rc = boot_select_or_erase(state, slot_usage);
            if (rc != 0) {
                /* The selected image slot has been erased. */
                slot_usage[BOOT_CURR_IMG(state)].slot_available[active_slot] = false;
                slot_usage[BOOT_CURR_IMG(state)].active_slot = NO_ACTIVE_SLOT;
                continue;
            }

            if (verbose)
            {
                for (int myslot = 0; myslot < 2; myslot++) {
                    if (slot_usage[BOOT_CURR_IMG(state)].slot_available[myslot] == true) {
                        dump_swap(myslot + 1);
                    }
                }
            }

            /* Image is first loaded to RAM and authenticated there in order to
             * prevent TOCTOU attack during image copy. This could be applied
             * when loading images from external (untrusted) flash to internal
             * (trusted) RAM and image is authenticated before copying.
             */
            rc = boot_load_image_to_sram(state, slot_usage);
            if (rc != 0 ) {
                /* Image cannot be ramloaded. */
                BOOT_LOG_ERR("%s: Image cannot be ramloaded!", __FUNCTION__);
                printf("%s: Image cannot be ramloaded!\n\n", __FUNCTION__);
                boot_remove_image_from_flash(state, active_slot);
                slot_usage[BOOT_CURR_IMG(state)].slot_available[active_slot] = false;
                slot_usage[BOOT_CURR_IMG(state)].active_slot = NO_ACTIVE_SLOT;
                continue;
            }

            FIH_CALL(boot_validate_slot, fih_rc, state, active_slot, NULL);
            if (fih_not_eq(fih_rc, FIH_SUCCESS)) {
                /* Image is invalid. */
                BOOT_LOG_ERR("%s: Image is invalid!!!", __FUNCTION__);
                boot_remove_image_from_sram(state, slot_usage);
                slot_usage[BOOT_CURR_IMG(state)].slot_available[active_slot] = false;
                slot_usage[BOOT_CURR_IMG(state)].active_slot = NO_ACTIVE_SLOT;
                continue;
            }

            /* Valid image loaded from a slot, go to next image. */
            break;
        }
    }

    FIH_RET(FIH_SUCCESS);
}

/********************************************************************* 
 * SCORPIO: We run a single (combined) image (BOOT_IMAGE_NUMBER == 1) 
 *********************************************************************/
fih_int
context_boot_go(struct boot_loader_state *state, struct boot_rsp *rsp)
{
    struct slot_usage_t slot_usage[BOOT_IMAGE_NUMBER];
    int rc;
    fih_int fih_rc = FIH_FAILURE;

    memset(state, 0, sizeof(struct boot_loader_state));
    memset(slot_usage, 0, sizeof(struct slot_usage_t) * BOOT_IMAGE_NUMBER);

    /* 
     * Fill in slots_available array (by checking headers) :
        slot_usage[BOOT_CURR_IMG(state)].slot_available[slot] = true;   //updates slot_aval
        slot_usage[BOOT_CURR_IMG(state)].active_slot = NO_ACTIVE_SLOT;  //Haven't picked active yet...
     */
    rc = boot_get_slot_usage(state, slot_usage);
    if (rc != 0) {
        goto out;
    }

    /* 
     * Check that all slots are loadable and decide which to boot.
     */
    FIH_CALL(boot_load_and_validate_images, fih_rc, state, slot_usage);
    if (fih_not_eq(fih_rc, FIH_SUCCESS)) {
        goto out;
    }

    /* All image loaded successfully. */
#ifdef MCUBOOT_HAVE_LOGGING
    print_loaded_images(state, slot_usage);
#endif

    fill_rsp(state, slot_usage, rsp);

out:
    close_all_flash_areas(state);

    if (fih_eq(fih_rc, FIH_SUCCESS)) {
        fih_rc = fih_int_encode(rc);
    }

    FIH_RET(fih_rc);
}

/**
 * Prepares the booting process. This function moves images around in flash as
 * appropriate, and tells you what address to boot from.
 *
 * @param rsp                   On success, indicates how booting should occur.
 *
 * @return                      FIH_SUCCESS on success; nonzero on failure.
 */
fih_int
boot_go(struct boot_rsp *rsp)
{
    fih_int fih_rc = FIH_FAILURE;
    FIH_CALL(context_boot_go, fih_rc, &boot_data, rsp);
    FIH_RET(fih_rc);
}
