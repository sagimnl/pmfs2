// SPDX-License-Identifier: GPL-2.0
/*
 * PMFS2 -- PMEM file-system in user-space via ZUFS.
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/*
 * PMFS2 code is a derived work from Intel's in-kernel PMEM file-system, which
 * itself is a derived work:
 *
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 */

#include "pmfs2.h"

const ushort PMFS2_VERSION[2] = { PMFS2_MAJOR_VERSION, PMFS2_MINOR_VERSION };
const char PMFS2_LICENSE[] = "GPL-2.0";
