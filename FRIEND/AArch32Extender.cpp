//
//  AArch32Extender.cpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 12/09/2017.
//  Copyright © 2017 Alexander Hude. All rights reserved.
//

#include <ida.hpp>
#include <idp.hpp>
#include <allins.hpp>
#include <regex>

#if IDA_SDK_VERSION >= 700
	#include <segregs.hpp>
#else
	#include <srarea.hpp>
#endif

#include "AArch32Extender.hpp"
#include "IDAAPI.hpp"

#ifdef __EA64__
	#define PRINTF_ADDR	"%llX"
#else
	#define PRINTF_ADDR	"%X"
#endif

#define BAIL_IF(cond, ...)		\
	do							\
	{							\
		if ((cond))				\
		{						\
			msg(__VA_ARGS__);	\
			goto bail;			\
		}						\
	}							\
	while (0)

const uint32_t kRegT = 20;

constexpr uint32_t MakeOpHash(uint32_t coproc, uint32_t opc1, uint32_t CRn, uint32_t CRm, uint32_t opc2 = 0)
{
	return ((coproc << 16) | (opc1 << 12) | (CRn << 8) | (CRm << 4) | (opc2 << 0));
}

// created using https://github.com/gdelugre/ida-arm-system-highlight and DDI0406C_C_armv7ar_arm.pdf
// { MakeOpHash(coproc, opc1, CRn, CRm, opc2),   "MNEMONIC" },      // Description
std::map<uint32_t, const char*> AArch32Extender::s_operandMap = {
	{ MakeOpHash(15, 0, 0, 0, 0),   "MIDR"          },      // Main ID Register
	{ MakeOpHash(15, 0, 0, 0, 1),   "CTR"           },      // Cache Type Register
	{ MakeOpHash(15, 0, 0, 0, 2),   "TCMTR"         },      // TCM Type Register
	{ MakeOpHash(15, 0, 0, 0, 3),   "TLBTR"         },      // TLB Type Register
	{ MakeOpHash(15, 0, 0, 0, 4),   "MIDR"          },      // alias to MIDR
	{ MakeOpHash(15, 0, 0, 0, 5),   "MPIDR"         },      // Multiprocessor Affinity Register
	{ MakeOpHash(15, 0, 0, 0, 6),   "REVIDR"        },      // Revision ID Register
	{ MakeOpHash(15, 0, 0, 0, 7),   "MIDR"          },      // alias to MIDR
	{ MakeOpHash(15, 0, 0, 1, 0),   "ID_PFR0"       },      // Processor Feature Register 0
	{ MakeOpHash(15, 0, 0, 1, 1),   "ID_PFR1"       },      // Processor Feature Register 1
	{ MakeOpHash(15, 0, 0, 1, 2),   "ID_DFR0"       },      // Debug Feature Register 0
	{ MakeOpHash(15, 0, 0, 1, 3),   "ID_AFR0"       },      // Auxiliary Feature Register 0
	{ MakeOpHash(15, 0, 0, 1, 4),   "ID_MMFR0"      },      // Memory Model Feature Register 0
	{ MakeOpHash(15, 0, 0, 1, 5),   "ID_MMFR1"      },      // Memory Model Feature Register 1
	{ MakeOpHash(15, 0, 0, 1, 6),   "ID_MMFR2"      },      // Memory Model Feature Register 2
	{ MakeOpHash(15, 0, 0, 1, 7),   "ID_MMFR3"      },      // Memory Model Feature Register 3
	{ MakeOpHash(15, 0, 0, 2, 6),   "ID_MMFR4"      },      // Memory Model Feature Register 4 (AArch32)
	{ MakeOpHash(15, 0, 0, 2, 0),   "ID_ISAR0"      },      // Instruction Set Attribute Register 0
	{ MakeOpHash(15, 0, 0, 2, 1),   "ID_ISAR1"      },      // Instruction Set Attribute Register 1
	{ MakeOpHash(15, 0, 0, 2, 2),   "ID_ISAR2"      },      // Instruction Set Attribute Register 2
	{ MakeOpHash(15, 0, 0, 2, 3),   "ID_ISAR3"      },      // Instruction Set Attribute Register 3
	{ MakeOpHash(15, 0, 0, 2, 4),   "ID_ISAR4"      },      // Instruction Set Attribute Register 4
	{ MakeOpHash(15, 0, 0, 2, 5),   "ID_ISAR5"      },      // Instruction Set Attribute Register 5
	{ MakeOpHash(15, 0, 0, 2, 7),   "ID_ISAR6"      },      // Instruction Set Attribute Register 6 (AArch32)
	{ MakeOpHash(15, 1, 0, 0, 0),   "CCSIDR"        },      // Current Cache Size ID Register
	{ MakeOpHash(15, 1, 0, 0, 2),   "CCSIDR2"       },      // Current Cache Size ID Register 2 (AArch32)
	{ MakeOpHash(15, 1, 0, 0, 1),   "CLIDR"         },      // Cache Level ID Register
	{ MakeOpHash(15, 1, 0, 0, 7),   "AIDR"          },      // Auxiliary ID Register
	{ MakeOpHash(15, 2, 0, 0, 0),   "CSSELR"        },      // Cache Size Selection Register
	{ MakeOpHash(15, 4, 0, 0, 0),   "VPIDR"         },      // Virtualization Processor ID Register
	{ MakeOpHash(15, 4, 0, 0, 5),   "VMPIDR"        },      // Virtualization Multiprocessor ID Register
	{ MakeOpHash(15, 0, 1, 0, 0),   "SCTLR"         },      // System Control Register
	{ MakeOpHash(15, 0, 1, 0, 1),   "ACTLR"         },      // Auxiliary Control Register
	{ MakeOpHash(15, 0, 1, 0, 3),   "ACTLR2"        },      // Auxiliary Control Register 2 (AArch32)
	{ MakeOpHash(15, 0, 1, 0, 2),   "CPACR"         },      // Architectural Feature Access Control Register
	{ MakeOpHash(15, 0, 1, 1, 0),   "SCR"           },      // Secure Configuration Register
	{ MakeOpHash(15, 0, 1, 1, 1),   "SDER"          },      // Secure Debug Enable Register
	{ MakeOpHash(15, 0, 1, 3, 1),   "SDCR"          },      // Secure Debug Control Register (AArch32)
	{ MakeOpHash(15, 0, 1, 1, 2),   "NSACR"         },      // Non-Secure Access Control Register
	{ MakeOpHash(15, 4, 1, 0, 0),   "HSCTLR"        },      // Hyp System Control Register
	{ MakeOpHash(15, 4, 1, 0, 1),   "HACTLR"        },      // Hyp Auxiliary Control Register
	{ MakeOpHash(15, 4, 1, 0, 3),   "HACTLR2"       },      // Hyp Auxiliary Control Register 2 (AArch32)
	{ MakeOpHash(15, 4, 1, 1, 0),   "HCR"           },      // Hyp Configuration Register
	{ MakeOpHash(15, 4, 1, 1, 4),   "HCR2"          },      // Hyp Configuration Register 2 (AArch32)
	{ MakeOpHash(15, 4, 1, 1, 1),   "HDCR"          },      // Hyp Debug Control Register
	{ MakeOpHash(15, 4, 1, 1, 2),   "HCPTR"         },      // Hyp Architectural Feature Trap Register
	{ MakeOpHash(15, 4, 1, 1, 3),   "HSTR"          },      // Hyp System Trap Register
	{ MakeOpHash(15, 4, 1, 1, 7),   "HACR"          },      // Hyp Auxiliary Configuration Register
	{ MakeOpHash(15, 0, 2, 0, 0),   "TTBR0"         },      // Translation Table Base Register 0
	{ MakeOpHash(15, 0, 2, 0, 1),   "TTBR1"         },      // Translation Table Base Register 1
	{ MakeOpHash(15, 0, 2, 0, 2),   "TTBCR"         },      // Translation Table Base Control Register
	{ MakeOpHash(15, 0, 2, 0, 3),   "TTBCR2"        },      // Translation Table Base Control Register 2 (AArch32)
	{ MakeOpHash(15, 4, 2, 0, 2),   "HTCR"          },      // Hyp Translation Control Register
	{ MakeOpHash(15, 4, 2, 1, 2),   "VTCR"          },      // Virtualization Translation Control Register
	{ MakeOpHash(15, 0, 3, 0, 0),   "DACR"          },      // Domain Access Control Register
	{ MakeOpHash(15, 0, 5, 0, 0),   "DFSR"          },      // Data Fault Status Register
	{ MakeOpHash(15, 0, 5, 0, 1),   "IFSR"          },      // Instruction Fault Status Register
	{ MakeOpHash(15, 0, 5, 1, 0),   "ADFSR"         },      // Auxiliary Data Fault Status Register
	{ MakeOpHash(15, 0, 5, 1, 1),   "AIFSR"         },      // Auxiliary Instruction Fault Status Register
	{ MakeOpHash(15, 4, 5, 1, 0),   "HADFSR"        },      // Hyp Auxiliary Data Fault Status Register
	{ MakeOpHash(15, 4, 5, 1, 1),   "HAIFSR"        },      // Hyp Auxiliary Instruction Fault Status Register
	{ MakeOpHash(15, 4, 5, 2, 0),   "HSR"           },      // Hyp Syndrome Register
	{ MakeOpHash(15, 0, 6, 0, 2),   "IFAR"          },      // Instruction Fault Address Register
	{ MakeOpHash(15, 4, 6, 0, 0),   "HDFAR"         },      // Hyp Data Fault Address Register
	{ MakeOpHash(15, 4, 6, 0, 2),   "HIFAR"         },      // Hyp Instruction Fault Address Register
	{ MakeOpHash(15, 4, 6, 0, 4),   "HPFAR"         },      // Hyp IPA Fault Address Register

	{ MakeOpHash(15, 0, 6, 0, 0),   "DFAR__NA_ProtBaseSizeDRegion0" }, // Data Fault Address Register / Base and Size Data Protection Region 0
	{ MakeOpHash(15, 0, 6, 1, 0),   "NA_ProtBaseSizeDRegion1" }, // Base and Size Data Protection Region 1
	{ MakeOpHash(15, 0, 6, 2, 0),   "NA_ProtBaseSizeDRegion2" }, // Base and Size Data Protection Region 2
	{ MakeOpHash(15, 0, 6, 3, 0),   "NA_ProtBaseSizeDRegion3" }, // Base and Size Data Protection Region 3
	{ MakeOpHash(15, 0, 6, 4, 0),   "NA_ProtBaseSizeDRegion4" }, // Base and Size Data Protection Region 4
	{ MakeOpHash(15, 0, 6, 5, 0),   "NA_ProtBaseSizeDRegion5" }, // Base and Size Data Protection Region 5
	{ MakeOpHash(15, 0, 6, 6, 0),   "NA_ProtBaseSizeDRegion6" }, // Base and Size Data Protection Region 6
	{ MakeOpHash(15, 0, 6, 7, 0),   "NA_ProtBaseSizeDRegion7" }, // Base and Size Data Protection Region 7
	{ MakeOpHash(15, 0, 6, 8, 0),   "NA_ProtBaseSizeDRegion8" }, // Base and Size Data Protection Region 8
	{ MakeOpHash(15, 0, 6, 9, 0),   "NA_ProtBaseSizeDRegion9" }, // Base and Size Data Protection Region 9
	{ MakeOpHash(15, 0, 6, 10, 0),   "NA_ProtBaseSizeDRegion10" }, // Base and Size Data Protection Region 10
	{ MakeOpHash(15, 0, 6, 11, 0),   "NA_ProtBaseSizeDRegion11" }, // Base and Size Data Protection Region 11
	{ MakeOpHash(15, 0, 6, 12, 0),   "NA_ProtBaseSizeDRegion12" }, // Base and Size Data Protection Region 12
	{ MakeOpHash(15, 0, 6, 13, 0),   "NA_ProtBaseSizeDRegion13" }, // Base and Size Data Protection Region 13
	{ MakeOpHash(15, 0, 6, 14, 0),   "NA_ProtBaseSizeDRegion14" }, // Base and Size Data Protection Region 14
	{ MakeOpHash(15, 0, 6, 15, 0),   "NA_ProtBaseSizeDRegion15" }, // Base and Size Data Protection Region 15
	
	{ MakeOpHash(15, 0, 6, 0, 1),   "WFAR__NA_ProtBaseSizeIRegion0" }, // Watchpoint Fault Address (AArch32) / Base and Size Instruction Protection Region 0
	{ MakeOpHash(15, 0, 6, 1, 1),   "NA_ProtBaseSizeIRegion1" }, // Base and Size Instruction Protection Region 1
	{ MakeOpHash(15, 0, 6, 2, 1),   "NA_ProtBaseSizeIRegion2" }, // Base and Size Instruction Protection Region 2
	{ MakeOpHash(15, 0, 6, 3, 1),   "NA_ProtBaseSizeIRegion3" }, // Base and Size Instruction Protection Region 3
	{ MakeOpHash(15, 0, 6, 4, 1),   "NA_ProtBaseSizeIRegion4" }, // Base and Size Instruction Protection Region 4
	{ MakeOpHash(15, 0, 6, 5, 1),   "NA_ProtBaseSizeIRegion5" }, // Base and Size Instruction Protection Region 5
	{ MakeOpHash(15, 0, 6, 6, 1),   "NA_ProtBaseSizeIRegion6" }, // Base and Size Instruction Protection Region 6
	{ MakeOpHash(15, 0, 6, 7, 1),   "NA_ProtBaseSizeIRegion7" }, // Base and Size Instruction Protection Region 7
	{ MakeOpHash(15, 0, 6, 8, 1),   "NA_ProtBaseSizeIRegion8" }, // Base and Size Instruction Protection Region 8
	{ MakeOpHash(15, 0, 6, 9, 1),   "NA_ProtBaseSizeIRegion9" }, // Base and Size Instruction Protection Region 9
	{ MakeOpHash(15, 0, 6, 10, 1),   "NA_ProtBaseSizeIRegion10" }, // Base and Size Instruction Protection Region 10
	{ MakeOpHash(15, 0, 6, 11, 1),   "NA_ProtBaseSizeIRegion11" }, // Base and Size Instruction Protection Region 11
	{ MakeOpHash(15, 0, 6, 12, 1),   "NA_ProtBaseSizeIRegion12" }, // Base and Size Instruction Protection Region 12
	{ MakeOpHash(15, 0, 6, 13, 1),   "NA_ProtBaseSizeIRegion13" }, // Base and Size Instruction Protection Region 13
	{ MakeOpHash(15, 0, 6, 14, 1),   "NA_ProtBaseSizeIRegion14" }, // Base and Size Instruction Protection Region 14
	{ MakeOpHash(15, 0, 6, 15, 1),   "NA_ProtBaseSizeIRegion15" }, // Base and Size Instruction Protection Region 15
	
	{ MakeOpHash(15, 0, 6, 1, 2),   "NA_RegSizeEnable" },   // Region Size and Enable Register
	{ MakeOpHash(15, 0, 6, 1, 4),   "NA_RegAccessControl" }, // Region Access Control Register

	// Cache Maintenance Registers
	{ MakeOpHash(15, 0, 7, 0, 4),   "NOP"           },      // No Operation / Wait For Interrupt / Unpredictable
	{ MakeOpHash(15, 0, 7, 1, 0),   "ICIALLUIS"     },      // Instruction Cache Invalidate All to PoU, Inner Shareable
	{ MakeOpHash(15, 0, 7, 1, 6),   "BPIALLIS"      },      // Branch Predictor Invalidate All, Inner Shareable
	{ MakeOpHash(15, 0, 7, 4, 0),   "PAR"           },      // Physical Address Register
	{ MakeOpHash(15, 0, 7, 5, 0),   "ICIALLU"       },      // Instruction Cache Invalidate All to PoU
	{ MakeOpHash(15, 0, 7, 5, 1),   "ICIMVAU"       },      // Instruction Cache line Invalidate by VA to PoU
	{ MakeOpHash(15, 0, 7, 5, 2),   "NA_InvAllICacheSetWay" }, // Invalidate all instruction caches by set/way *
	{ MakeOpHash(15, 0, 7, 5, 4),   "CP15ISB"       },      // Instruction Synchronization Barrier System instruction
	{ MakeOpHash(15, 0, 7, 5, 6),   "BPIALL"        },      // Branch Predictor Invalidate All
	{ MakeOpHash(15, 0, 7, 5, 7),   "BPIMVA"        },      // Branch Predictor Invalidate by VA
	{ MakeOpHash(15, 0, 7, 6, 0),   "NA_InvAllDCache" }, 	// Invalidate entire data cache *
	{ MakeOpHash(15, 0, 7, 6, 1),   "DCIMVAC"       },      // Data Cache line Invalidate by VA to PoC
	{ MakeOpHash(15, 0, 7, 6, 2),   "DCISW"         },      // Data Cache line Invalidate by Set/Way
	{ MakeOpHash(15, 0, 7, 7, 0),   "NA_InvInDCache" }, 	// Invalidate instruction cache and data cache" *
	{ MakeOpHash(15, 0, 7, 8, 0),   "ATS1CPR"       },      // Address Translate Stage 1 Current state PL1 Read
	{ MakeOpHash(15, 0, 7, 8, 1),   "ATS1CPW"       },      // Address Translate Stage 1 Current state PL1 Write
	{ MakeOpHash(15, 0, 7, 8, 2),   "ATS1CUR"       },      // Address Translate Stage 1 Current state Unprivileged Read
	{ MakeOpHash(15, 0, 7, 8, 3),   "ATS1CUW"       },      // Address Translate Stage 1 Current state Unprivileged Write
	{ MakeOpHash(15, 0, 7, 8, 4),   "ATS12NSOPR"    },      // Address Translate Stages 1 and 2 Non-secure Only PL1 Read
	{ MakeOpHash(15, 0, 7, 8, 5),   "ATS12NSOPW"    },      // Address Translate Stages 1 and 2 Non-secure Only PL1 Write
	{ MakeOpHash(15, 0, 7, 8, 6),   "ATS12NSOUR"    },      // Address Translate Stages 1 and 2 Non-secure Only Unprivileged Read
	{ MakeOpHash(15, 0, 7, 8, 7),   "ATS12NSOUW"    },      // Address Translate Stages 1 and 2 Non-secure Only Unprivileged Write
	{ MakeOpHash(15, 0, 7, 9, 0),   "ATS1CPRP"      },      // Address Translate Stage 1 Current state PL1 Read PAN (AArch32)
	{ MakeOpHash(15, 0, 7, 9, 1),   "ATS1CPWP"      },      // Address Translate Stage 1 Current state PL1 Write PAN (AArch32)
	{ MakeOpHash(15, 0, 7, 10, 0),  "NA_CleanDCache" },  	// Clean entire data cache
	{ MakeOpHash(15, 0, 7, 10, 1),  "DCCMVAC"       },      // Data Cache line Clean by VA to PoC
	{ MakeOpHash(15, 0, 7, 10, 2),  "DCCSW"         },      // Data Cache line Clean by Set/Way
	{ MakeOpHash(15, 0, 7, 10, 3),  "NA_TestCleanDCache" }, // Test and clean data cache
	{ MakeOpHash(15, 0, 7, 10, 4),  "CP15DSB"       },      // Data Synchronization Barrier System instruction
	{ MakeOpHash(15, 0, 7, 10, 5),  "CP15DMB"       },      // Data Memory Barrier System instruction
	{ MakeOpHash(15, 0, 7, 10, 6),  "NA_ReadCacheDirtyStatReg" }, // Read Cache Dirty Status Register
	{ MakeOpHash(15, 0, 7, 11, 1),  "DCCMVAU"       },      // Data Cache line Clean by VA to PoU
	{ MakeOpHash(15, 0, 7, 12, 4),  "NA_ReadBlockTransStatRer" }, // Read Block Transfer Status Register
	{ MakeOpHash(15, 0, 7, 12, 5),  "NA_StopPrefetchRange" }, // Stop Prefetch Range
	{ MakeOpHash(15, 0, 7, 13, 1),  "NOP"           },      // No Operation / Prefetch Instruction Cache Line
	{ MakeOpHash(15, 0, 7, 14, 0),  "NA_CleanInvAllDCache" }, // Clean and invalidate entire data cache
	{ MakeOpHash(15, 0, 7, 14, 1),  "DCCIMVAC"      },      // Data Cache line Clean and Invalidate by VA to PoC
	{ MakeOpHash(15, 0, 7, 14, 2),  "DCCISW"        },      // Data Cache line Clean and Invalidate by Set/Way
	{ MakeOpHash(15, 0, 7, 14, 3),  "NA_TestCleanInvDCache" }, // Test, clean, and invalidate data cache
	{ MakeOpHash(15, 4, 7, 8, 0),   "ATS1HR"        },      // Address Translate Stage 1 Hyp mode Read
	{ MakeOpHash(15, 4, 7, 8, 1),   "ATS1HW"        },      // Stage 1 Hyp mode write
	
	// TLB maintenance operations
	{ MakeOpHash(15, 0, 8, 3, 0),   "TLBIALLIS"     },      // TLB Invalidate All, Inner Shareable
	{ MakeOpHash(15, 0, 8, 3, 1),   "TLBIMVAIS"     },      // TLB Invalidate by VA, Inner Shareable
	{ MakeOpHash(15, 0, 8, 3, 2),   "TLBIASIDIS"    },      // TLB Invalidate by ASID match, Inner Shareable
	{ MakeOpHash(15, 0, 8, 3, 3),   "TLBIMVAAIS"    },      // TLB Invalidate by VA, All ASID, Inner Shareable
	{ MakeOpHash(15, 0, 8, 3, 5),   "TLBIMVALIS"    },      // TLB Invalidate by VA, Last level, Inner Shareable (AArch32)
	{ MakeOpHash(15, 0, 8, 3, 7),   "TLBIMVAALIS"   },      // TLB Invalidate by VA, All ASID, Last level, Inner Shareable (AArch32)
	{ MakeOpHash(15, 0, 8, 5, 0),   "ITLBIALL"      },      // Instruction TLB Invalidate All
	{ MakeOpHash(15, 0, 8, 5, 1),   "ITLBIMVA"      },      // Instruction TLB Invalidate by VA
	{ MakeOpHash(15, 0, 8, 5, 2),   "ITLBIASID"     },      // Instruction TLB Invalidate by ASID match
	{ MakeOpHash(15, 0, 8, 6, 0),   "DTLBIALL"      },      // Data TLB Invalidate All
	{ MakeOpHash(15, 0, 8, 6, 1),   "DTLBIMVA"      },      // Data TLB Invalidate by VA
	{ MakeOpHash(15, 0, 8, 6, 2),   "DTLBIASID"     },      // Data TLB Invalidate by ASID match
	{ MakeOpHash(15, 0, 8, 7, 0),   "TLBIALL"       },      // TLB Invalidate All
	{ MakeOpHash(15, 0, 8, 7, 1),   "TLBIMVA"       },      // TLB Invalidate by VA
	{ MakeOpHash(15, 0, 8, 7, 2),   "TLBIASID"      },      // TLB Invalidate by ASID match
	{ MakeOpHash(15, 0, 8, 7, 3),   "TLBIMVAA"      },      // TLB Invalidate by VA, All ASID
	{ MakeOpHash(15, 0, 8, 7, 5),   "TLBIMVAL"      },      // TLB Invalidate by VA, Last level (AArch32)
	{ MakeOpHash(15, 0, 8, 7, 7),   "TLBIMVAAL"     },      // TLB Invalidate by VA, All ASID, Last level (AArch32)
	{ MakeOpHash(15, 4, 8, 0, 1),   "TLBIIPAS2IS"   },      // TLB Invalidate by Intermediate Physical Address, Stage 2, Inner Shareable (AArch32)
	{ MakeOpHash(15, 4, 8, 0, 5),   "TLBIIPAS2LIS"  },      // TLB Invalidate by Intermediate Physical Address, Stage 2, Last level, Inner Shareable (AArch32)
	{ MakeOpHash(15, 4, 8, 3, 0),   "TLBIALLHIS"    },      // TLB Invalidate All, Hyp mode, Inner Shareable
	{ MakeOpHash(15, 4, 8, 3, 1),   "TLBIMVAHIS"    },      // TLB Invalidate by VA, Hyp mode, Inner Shareable
	{ MakeOpHash(15, 4, 8, 3, 4),   "TLBIALLNSNHIS" },      // TLB Invalidate All, Non-Secure Non-Hyp, Inner Shareable
	{ MakeOpHash(15, 4, 8, 3, 5),   "TLBIMVALHIS"   },      // TLB Invalidate by VA, Last level, Hyp mode, Inner Shareable (AArch32)
	{ MakeOpHash(15, 4, 8, 4, 1),   "TLBIIPAS2"     },      // TLB Invalidate by Intermediate Physical Address, Stage 2 (AArch32)
	{ MakeOpHash(15, 4, 8, 4, 5),   "TLBIIPAS2L"    },      // TLB Invalidate by Intermediate Physical Address, Stage 2, Last level (AArch32)
	{ MakeOpHash(15, 4, 8, 7, 0),   "TLBIALLH"      },      // TLB Invalidate All, Hyp mode
	{ MakeOpHash(15, 4, 8, 7, 1),   "TLBIMVAH"      },      // TLB Invalidate by VA, Hyp mode
	{ MakeOpHash(15, 4, 8, 7, 4),   "TLBIALLNSNH"   },      // TLB Invalidate All, Non-Secure Non-Hyp
	{ MakeOpHash(15, 4, 8, 7, 5),   "TLBIMVALH"     },      // TLB Invalidate by VA, Last level, Hyp mode (AArch32)
	
	{ MakeOpHash(15, 0, 9, 0, 0),   "NA_DCacheLock" },      // Data Cache Lockdown
	{ MakeOpHash(15, 0, 9, 0, 1),   "NA_ICacheLock" },      // Instruction Cache Lockdown
	{ MakeOpHash(15, 0, 9, 1, 0),   "NA_DTCMRegion" },   	// Data TCM Region
	{ MakeOpHash(15, 0, 9, 1, 1),   "NA_ITCMRegion" },      // Instruction TCM Region
	{ MakeOpHash(15, 1, 9, 0, 2),   "L2CTLR"        },      // L2 Control Register (AArch32)
	{ MakeOpHash(15, 1, 9, 0, 3),   "L2ECTLR"       },      // L2 Extended Control Register (AArch32)
	
	// Performance Monitor Registers
	{ MakeOpHash(15, 0, 9, 12, 0),  "PMCR"          },      // Performance Monitors Control Register
	{ MakeOpHash(15, 0, 9, 12, 1),  "PMCNTENSET"    },      // Performance Monitor Count Enable Set Register
	{ MakeOpHash(15, 0, 9, 12, 2),  "PMCNTENCLR"    },      // Performance Monitor Control Enable Clear Register
	{ MakeOpHash(15, 0, 9, 12, 3),  "PMOVSR"        },      // Performance Monitors Overflow Flag Status Register
	{ MakeOpHash(15, 0, 9, 12, 4),  "PMSWINC"       },      // Performance Monitors Software Increment register
	{ MakeOpHash(15, 0, 9, 12, 5),  "PMSELR"        },      // Performance Monitors Event Counter Selection Register
	{ MakeOpHash(15, 0, 9, 12, 6),  "PMCEID0"       },      // Performance Monitors Common Event Identification register 0
	{ MakeOpHash(15, 0, 9, 12, 7),  "PMCEID1"       },      // Performance Monitors Common Event Identification register 1
	{ MakeOpHash(15, 0, 9, 13, 0),  "PMCCNTR"       },      // Performance Monitors Cycle Count Register
	{ MakeOpHash(15, 0, 9, 13, 1),  "PMXEVTYPER"    },      // Performance Monitors Selected Event Type Register
	{ MakeOpHash(15, 0, 9, 13, 2),  "PMXEVCNTR"     },      // Performance Monitors Selected Event Count Register
	{ MakeOpHash(15, 0, 9, 14, 0),  "PMUSERENR"     },      // Performance Monitors User Enable Register
	{ MakeOpHash(15, 0, 9, 14, 1),  "PMINTENSET"    },      // Performance Monitors Interrupt Enable Set register
	{ MakeOpHash(15, 0, 9, 14, 2),  "PMINTENCLR"    },      // Performance Monitors Interrupt Enable Clear register
	{ MakeOpHash(15, 0, 9, 14, 3),  "PMOVSSET"      },      // Performance Monitors Overflow Flag Status Set register
	
	{ MakeOpHash(15, 0, 9, 14, 4),  "PMCEID2"       },      // Performance Monitors Common Event Identification register 2 (AArch32)
	{ MakeOpHash(15, 0, 9, 14, 5),  "PMCEID3"       },      // Performance Monitors Common Event Identification register 3 (AArch32)
	{ MakeOpHash(15, 0, 14, 8, 0),  "PMEVCNTR0"     },      // Performance Monitors Event Count Register 0 (AArch32)
	{ MakeOpHash(15, 0, 14, 8, 1),  "PMEVCNTR1"     },      // Performance Monitors Event Count Register 1 (AArch32)
	{ MakeOpHash(15, 0, 14, 8, 2),  "PMEVCNTR2"     },      // Performance Monitors Event Count Register 2 (AArch32)
	{ MakeOpHash(15, 0, 14, 8, 3),  "PMEVCNTR3"     },      // Performance Monitors Event Count Register 3 (AArch32)
	{ MakeOpHash(15, 0, 14, 8, 4),  "PMEVCNTR4"     },      // Performance Monitors Event Count Register 4 (AArch32)
	{ MakeOpHash(15, 0, 14, 8, 5),  "PMEVCNTR5"     },      // Performance Monitors Event Count Register 5 (AArch32)
	{ MakeOpHash(15, 0, 14, 8, 6),  "PMEVCNTR6"     },      // Performance Monitors Event Count Register 6 (AArch32)
	{ MakeOpHash(15, 0, 14, 8, 7),  "PMEVCNTR7"     },      // Performance Monitors Event Count Register 7 (AArch32)
	{ MakeOpHash(15, 0, 14, 9, 0),  "PMEVCNTR8"     },      // Performance Monitors Event Count Register 8 (AArch32)
	{ MakeOpHash(15, 0, 14, 9, 1),  "PMEVCNTR9"     },      // Performance Monitors Event Count Register 9 (AArch32)
	{ MakeOpHash(15, 0, 14, 9, 2),  "PMEVCNTR10"    },      // Performance Monitors Event Count Register 10 (AArch32)
	{ MakeOpHash(15, 0, 14, 9, 3),  "PMEVCNTR11"    },      // Performance Monitors Event Count Register 11 (AArch32)
	{ MakeOpHash(15, 0, 14, 9, 4),  "PMEVCNTR12"    },      // Performance Monitors Event Count Register 12 (AArch32)
	{ MakeOpHash(15, 0, 14, 9, 5),  "PMEVCNTR13"    },      // Performance Monitors Event Count Register 13 (AArch32)
	{ MakeOpHash(15, 0, 14, 9, 6),  "PMEVCNTR14"    },      // Performance Monitors Event Count Register 14 (AArch32)
	{ MakeOpHash(15, 0, 14, 9, 7),  "PMEVCNTR15"    },      // Performance Monitors Event Count Register 15 (AArch32)
	{ MakeOpHash(15, 0, 14, 10, 0), "PMEVCNTR16"    },      // Performance Monitors Event Count Register 16 (AArch32)
	{ MakeOpHash(15, 0, 14, 10, 1), "PMEVCNTR17"    },      // Performance Monitors Event Count Register 17 (AArch32)
	{ MakeOpHash(15, 0, 14, 10, 2), "PMEVCNTR18"    },      // Performance Monitors Event Count Register 18 (AArch32)
	{ MakeOpHash(15, 0, 14, 10, 3), "PMEVCNTR19"    },      // Performance Monitors Event Count Register 19 (AArch32)
	{ MakeOpHash(15, 0, 14, 10, 4), "PMEVCNTR20"    },      // Performance Monitors Event Count Register 20 (AArch32)
	{ MakeOpHash(15, 0, 14, 10, 5), "PMEVCNTR21"    },      // Performance Monitors Event Count Register 21 (AArch32)
	{ MakeOpHash(15, 0, 14, 10, 6), "PMEVCNTR22"    },      // Performance Monitors Event Count Register 22 (AArch32)
	{ MakeOpHash(15, 0, 14, 10, 7), "PMEVCNTR23"    },      // Performance Monitors Event Count Register 23 (AArch32)
	{ MakeOpHash(15, 0, 14, 11, 0), "PMEVCNTR24"    },      // Performance Monitors Event Count Register 24 (AArch32)
	{ MakeOpHash(15, 0, 14, 11, 1), "PMEVCNTR25"    },      // Performance Monitors Event Count Register 25 (AArch32)
	{ MakeOpHash(15, 0, 14, 11, 2), "PMEVCNTR26"    },      // Performance Monitors Event Count Register 26 (AArch32)
	{ MakeOpHash(15, 0, 14, 11, 3), "PMEVCNTR27"    },      // Performance Monitors Event Count Register 27 (AArch32)
	{ MakeOpHash(15, 0, 14, 11, 4), "PMEVCNTR28"    },      // Performance Monitors Event Count Register 28 (AArch32)
	{ MakeOpHash(15, 0, 14, 11, 5), "PMEVCNTR29"    },      // Performance Monitors Event Count Register 29 (AArch32)
	{ MakeOpHash(15, 0, 14, 11, 6), "PMEVCNTR30"    },      // Performance Monitors Event Count Register 30 (AArch32)
	{ MakeOpHash(15, 0, 14, 12, 0), "PMEVTYPER0"    },      // Performance Monitors Event Type Register 0 (AArch32)
	{ MakeOpHash(15, 0, 14, 12, 1), "PMEVTYPER1"    },      // Performance Monitors Event Type Register 1 (AArch32)
	{ MakeOpHash(15, 0, 14, 12, 2), "PMEVTYPER2"    },      // Performance Monitors Event Type Register 2 (AArch32)
	{ MakeOpHash(15, 0, 14, 12, 3), "PMEVTYPER3"    },      // Performance Monitors Event Type Register 3 (AArch32)
	{ MakeOpHash(15, 0, 14, 12, 4), "PMEVTYPER4"    },      // Performance Monitors Event Type Register 4 (AArch32)
	{ MakeOpHash(15, 0, 14, 12, 5), "PMEVTYPER5"    },      // Performance Monitors Event Type Register 5 (AArch32)
	{ MakeOpHash(15, 0, 14, 12, 6), "PMEVTYPER6"    },      // Performance Monitors Event Type Register 6 (AArch32)
	{ MakeOpHash(15, 0, 14, 12, 7), "PMEVTYPER7"    },      // Performance Monitors Event Type Register 7 (AArch32)
	{ MakeOpHash(15, 0, 14, 13, 0), "PMEVTYPER8"    },      // Performance Monitors Event Type Register 8 (AArch32)
	{ MakeOpHash(15, 0, 14, 13, 1), "PMEVTYPER9"    },      // Performance Monitors Event Type Register 9 (AArch32)
	{ MakeOpHash(15, 0, 14, 13, 2), "PMEVTYPER10"   },      // Performance Monitors Event Type Register 10 (AArch32)
	{ MakeOpHash(15, 0, 14, 13, 3), "PMEVTYPER11"   },      // Performance Monitors Event Type Register 11 (AArch32)
	{ MakeOpHash(15, 0, 14, 13, 4), "PMEVTYPER12"   },      // Performance Monitors Event Type Register 12 (AArch32)
	{ MakeOpHash(15, 0, 14, 13, 5), "PMEVTYPER13"   },      // Performance Monitors Event Type Register 13 (AArch32)
	{ MakeOpHash(15, 0, 14, 13, 6), "PMEVTYPER14"   },      // Performance Monitors Event Type Register 14 (AArch32)
	{ MakeOpHash(15, 0, 14, 13, 7), "PMEVTYPER15"   },      // Performance Monitors Event Type Register 15 (AArch32)
	{ MakeOpHash(15, 0, 14, 14, 0), "PMEVTYPER16"   },      // Performance Monitors Event Type Register 16 (AArch32)
	{ MakeOpHash(15, 0, 14, 14, 1), "PMEVTYPER17"   },      // Performance Monitors Event Type Register 17 (AArch32)
	{ MakeOpHash(15, 0, 14, 14, 2), "PMEVTYPER18"   },      // Performance Monitors Event Type Register 18 (AArch32)
	{ MakeOpHash(15, 0, 14, 14, 3), "PMEVTYPER19"   },      // Performance Monitors Event Type Register 19 (AArch32)
	{ MakeOpHash(15, 0, 14, 14, 4), "PMEVTYPER20"   },      // Performance Monitors Event Type Register 20 (AArch32)
	{ MakeOpHash(15, 0, 14, 14, 5), "PMEVTYPER21"   },      // Performance Monitors Event Type Register 21 (AArch32)
	{ MakeOpHash(15, 0, 14, 14, 6), "PMEVTYPER22"   },      // Performance Monitors Event Type Register 22 (AArch32)
	{ MakeOpHash(15, 0, 14, 14, 7), "PMEVTYPER23"   },      // Performance Monitors Event Type Register 23 (AArch32)
	{ MakeOpHash(15, 0, 14, 15, 0), "PMEVTYPER24"   },      // Performance Monitors Event Type Register 24 (AArch32)
	{ MakeOpHash(15, 0, 14, 15, 1), "PMEVTYPER25"   },      // Performance Monitors Event Type Register 25 (AArch32)
	{ MakeOpHash(15, 0, 14, 15, 2), "PMEVTYPER26"   },      // Performance Monitors Event Type Register 26 (AArch32)
	{ MakeOpHash(15, 0, 14, 15, 3), "PMEVTYPER27"   },      // Performance Monitors Event Type Register 27 (AArch32)
	{ MakeOpHash(15, 0, 14, 15, 4), "PMEVTYPER28"   },      // Performance Monitors Event Type Register 28 (AArch32)
	{ MakeOpHash(15, 0, 14, 15, 5), "PMEVTYPER29"   },      // Performance Monitors Event Type Register 29 (AArch32)
	{ MakeOpHash(15, 0, 14, 15, 6), "PMEVTYPER30"   },      // Performance Monitors Event Type Register 30 (AArch32)
	{ MakeOpHash(15, 0, 14, 15, 7), "PMCCFILTR"     },      // Performance Monitors Cycle Count Filter Register (AArch32)
	
	// Memory Attribute Registers
	{ MakeOpHash(15, 0, 10, 0, 0),  "NA_TLBLock"    },      // TLB Lockdown
	{ MakeOpHash(15, 0, 10, 2, 0),  "MAIR0"         },      // Memory Attribute Indirection Register 0 / PRRR - Primary Region Remap Register
	{ MakeOpHash(15, 0, 10, 2, 1),  "MAIR1"         },      // Memory Attribute Indirection Register 1 / NMRR - Normal Memory Remap Register
	{ MakeOpHash(15, 0, 10, 3, 0),  "AMAIR0"        },      // Auxiliary Memory Attribute Indirection Register 0
	{ MakeOpHash(15, 0, 10, 3, 1),  "AMAIR1"        },      // Auxiliary Memory Attribute Indirection Register 1
	{ MakeOpHash(15, 4, 10, 2, 0),  "HMAIR0"        },      // Hyp Memory Attribute Indirection Register 0
	{ MakeOpHash(15, 4, 10, 2, 1),  "HMAIR1"        },      // Hyp Memory Attribute Indirection Register 1
	{ MakeOpHash(15, 4, 10, 3, 0),  "HAMAIR0"       },      // Hyp Auxiliary Memory Attribute Indirection Register 0
	{ MakeOpHash(15, 4, 10, 3, 1),  "HAMAIR1"       },      // Hyp Auxiliary Memory Attribute Indirection Register 1
	
	// DMA Registers (ARM11)
	{ MakeOpHash(15, 0, 11, 0, 0),  "NA_DMAIdStatPresent" }, // DMA Identification and Status (Present)
	{ MakeOpHash(15, 0, 11, 0, 1),  "NA_DMAIdStatQueued" }, // DMA Identification and Status (Queued)
	{ MakeOpHash(15, 0, 11, 0, 2),  "NA_DMAIdStatRunning" }, // DMA Identification and Status (Running)
	{ MakeOpHash(15, 0, 11, 0, 3),  "NA_DMAIdStatInt" },   // DMA Identification and Status (Interrupting)
	{ MakeOpHash(15, 0, 11, 1, 0),  "NA_DMAUserAccess" },  // DMA User Accessibility
	{ MakeOpHash(15, 0, 11, 2, 0),  "NA_DMAChNum"  },      // DMA Channel Number)
	{ MakeOpHash(15, 0, 11, 3, 0),  "NA_DMAEnableStop" },  // DMA Enable (Stop)
	{ MakeOpHash(15, 0, 11, 3, 1),  "NA_DMAEnableStart" }, // DMA Enable (Start)
	{ MakeOpHash(15, 0, 11, 3, 2),  "NA_DMAEnableClean" }, // DMA Enable (Clear)
	{ MakeOpHash(15, 0, 11, 4, 0),  "NA_DMAControl" },     // DMA Control
	{ MakeOpHash(15, 0, 11, 5, 0),  "NA_DMAIntStartAddr" }, // DMA Internal Start Address
	{ MakeOpHash(15, 0, 11, 6, 0),  "NA_DMAExtStartAddr" }, // DMA External Start Address
	{ MakeOpHash(15, 0, 11, 7, 0),  "NA_DMAIntEndAddr" },   // DMA Internal End Address
	{ MakeOpHash(15, 0, 11, 8, 0),  "NA_DMAChStatus" },     // DMA Channel Status
	{ MakeOpHash(15, 0, 11, 15, 0), "NA_DMAContextID" },    // DMA Context ID
	
	// Reset Management Registers.
	{ MakeOpHash(15, 0, 12, 0, 0),  "VBAR"          },      // Vector Base Address Register
	{ MakeOpHash(15, 0, 12, 0, 1),  "RVBAR"         },      // Reset Vector Base Address Register (RVBAR) / Monitor Vector Base Address Register (MVBAR)
	{ MakeOpHash(15, 0, 12, 0, 2),  "RMR"           },      // Reset Management Register (AArch32)
	{ MakeOpHash(15, 4, 12, 0, 2),  "HRMR"          },      // Hyp Reset Management Register (AArch32)
	
	{ MakeOpHash(15, 0, 12, 1, 0),  "ISR"           },      // Interrupt Status Register
	{ MakeOpHash(15, 4, 12, 0, 0),  "HVBAR"         },      // Hyp Vector Base Address Register
	
	{ MakeOpHash(15, 0, 13, 0, 0),  "FCSEIDR"       },      // FCSE Process ID register
	{ MakeOpHash(15, 0, 13, 0, 1),  "CONTEXTIDR"    },      // Context ID Register
	{ MakeOpHash(15, 0, 13, 0, 2),  "TPIDRURW"      },      // PL0 Read/Write Software Thread ID Register
	{ MakeOpHash(15, 0, 13, 0, 3),  "TPIDRURO"      },      // PL0 Read-Only Software Thread ID Register
	{ MakeOpHash(15, 0, 13, 0, 4),  "TPIDRPRW"      },      // PL1 Software Thread ID Register
	{ MakeOpHash(15, 4, 13, 0, 2),  "HTPIDR"        },      // Hyp Software Thread ID Register
	
	// Generic Timer Registers.
	{ MakeOpHash(15, 0, 14, 0, 0),  "CNTFRQ"        },      // Counter-timer Frequency register
	{ MakeOpHash(15, 0, 14, 1, 0),  "CNTKCTL"       },      // Counter-timer Kernel Control register
	{ MakeOpHash(15, 0, 14, 2, 0),  "CNTP_TVAL"     },      // Counter-timer Physical Timer TimerValue (CNTP_TVAL) / Counter-timer Hyp Physical Timer TimerValue register (CNTHP_TVAL)
	{ MakeOpHash(15, 0, 14, 2, 1),  "CNTP_CTL"      },      // Counter-timer Physical Timer Control (CNTP_CTL) / Counter-timer Hyp Physical Timer Control register (CNTHP_CTL)
	{ MakeOpHash(15, 0, 14, 3, 0),  "CNTV_TVAL"     },      // Counter-timer Virtual Timer TimerValue (CNTV_TVAL) / Counter-timer Virtual Timer TimerValue register (EL2) (CNTHV_TVAL)
	{ MakeOpHash(15, 0, 14, 3, 1),  "CNTV_CTL"      },      // Counter-timer Virtual Timer Control (CNTV_CTL) / Counter-timer Virtual Timer Control register (EL2) (CNTHV_CTL)
	{ MakeOpHash(15, 4, 14, 1, 0),  "CNTHCTL"       },      // Counter-timer Hyp Control register
	{ MakeOpHash(15, 4, 14, 2, 0),  "CNTHP_TVAL"    },      // Counter-timer Hyp Physical Timer TimerValue register
	{ MakeOpHash(15, 4, 14, 2, 1),  "CNTHP_CTL"     },      // Counter-timer Hyp Physical Timer Control register
	
	// Generic Interrupt Controller Registers (AArch32)
	{ MakeOpHash(15, 0, 4, 6, 0),   "ICC_PMR"       },      // Interrupt Controller Interrupt Priority Mask (ICC_PMR) / Interrupt Controller Virtual Interrupt Priority Mask Register (ICV_PMR)
	{ MakeOpHash(15, 0, 12, 8, 0),  "ICC_IAR0"      },      // Interrupt Controller Interrupt Acknowledge Register (ICC_IAR0) / Interrupt Controller Virtual Interrupt Acknowledge Register 0 (ICV_IAR0)
	{ MakeOpHash(15, 0, 12, 8, 1),  "ICC_EOIR0"     },      // Interrupt Controller End Of Interrupt Register (ICC_EOIR0) / Interrupt Controller Virtual End Of Interrupt Register 0 (ICV_EOIR0)
	{ MakeOpHash(15, 0, 12, 8, 2),  "ICC_HPPIR0"    },      // Interrupt Controller Highest Priority Pending Interrupt Register (ICC_HPPIR0) / Interrupt Controller Virtual Highest Priority Pending Interrupt Register 0 (ICV_HPPIR0)
	{ MakeOpHash(15, 0, 12, 8, 3),  "ICC_BPR0"      },      // Interrupt Controller Binary Point Register (ICC_BPR0) / Interrupt Controller Virtual Binary Point Register 0 (ICV_BPR0)
	{ MakeOpHash(15, 0, 12, 8, 4),  "ICC_AP0R0"     },      // Interrupt Controller Active Priorities Group 0 Register (ICC_AP0R0) / Interrupt Controller Virtual Active Priorities Group 0 Register 0 (ICV_AP0R0)
	{ MakeOpHash(15, 0, 12, 8, 5),  "ICC_AP0R1"     },      // Interrupt Controller Active Priorities Group 0 Register (ICC_AP0R1) / Interrupt Controller Virtual Active Priorities Group 0 Register 1 (ICV_AP0R1)
	{ MakeOpHash(15, 0, 12, 8, 6),  "ICC_AP0R2"     },      // Interrupt Controller Active Priorities Group 0 Register (ICC_AP0R2) / Interrupt Controller Virtual Active Priorities Group 0 Register 2 (ICV_AP0R2)
	{ MakeOpHash(15, 0, 12, 8, 7),  "ICC_AP0R3"     },      // Interrupt Controller Active Priorities Group 0 Register (ICC_AP0R3) / Interrupt Controller Virtual Active Priorities Group 0 Register 3 (ICV_AP0R3)
	{ MakeOpHash(15, 0, 12, 9, 0),  "ICC_AP1R0"     },      // Interrupt Controller Active Priorities Group 1 Register (ICC_AP1R0) / Interrupt Controller Virtual Active Priorities Group 1 Register 0 (ICV_AP1R0)
	{ MakeOpHash(15, 0, 12, 9, 1),  "ICC_AP1R1"     },      // Interrupt Controller Active Priorities Group 1 Register (ICC_AP1R1) / Interrupt Controller Virtual Active Priorities Group 1 Register 1 (ICV_AP1R1)
	{ MakeOpHash(15, 0, 12, 9, 2),  "ICC_AP1R2"     },      // Interrupt Controller Active Priorities Group 1 Register (ICC_AP1R2) / Interrupt Controller Virtual Active Priorities Group 1 Register 2 (ICV_AP1R2)
	{ MakeOpHash(15, 0, 12, 9, 3),  "ICC_AP1R3"     },      // Interrupt Controller Active Priorities Group 1 Register (ICC_AP1R3) / Interrupt Controller Virtual Active Priorities Group 1 Register 3 (ICV_AP1R3)
	{ MakeOpHash(15, 0, 12, 11, 1), "ICC_DIR"       },      // Interrupt Controller Deactivate Interrupt (ICC_DIR) / Interrupt Controller Deactivate Virtual Interrupt Register (ICV_DIR)
	{ MakeOpHash(15, 0, 12, 11, 3), "ICC_RPR"       },      // Interrupt Controller Running Priority (ICC_RPR) / Interrupt Controller Virtual Running Priority Register (ICV_RPR)
	{ MakeOpHash(15, 0, 12, 12, 0), "ICC_IAR1"      },      // Interrupt Controller Interrupt Acknowledge Register (ICC_IAR1) / Interrupt Controller Virtual Interrupt Acknowledge Register 1 (ICV_IAR1)
	{ MakeOpHash(15, 0, 12, 12, 1), "ICC_EOIR1"     },      // Interrupt Controller End Of Interrupt Register (ICC_EOIR1) / Interrupt Controller Virtual End Of Interrupt Register 1 (ICV_EOIR1)
	{ MakeOpHash(15, 0, 12, 12, 2), "ICC_HPPIR1"    },      // Interrupt Controller Highest Priority Pending Interrupt Register (ICC_HPPIR1) / Interrupt Controller Virtual Highest Priority Pending Interrupt Register 1 (ICV_HPPIR1)
	{ MakeOpHash(15, 0, 12, 12, 3), "ICC_BPR1"      },      // Interrupt Controller Binary Point Register (ICC_BPR1) / Interrupt Controller Virtual Binary Point Register 1 (ICV_BPR1)
	{ MakeOpHash(15, 0, 12, 12, 4), "ICC_CTLR"      },      // Interrupt Controller Control (ICC_CTLR) / Interrupt Controller Virtual Control Register (ICV_CTLR)
	{ MakeOpHash(15, 0, 12, 12, 5), "ICC_SRE"       },      // Interrupt Controller System Register Enable register
	{ MakeOpHash(15, 0, 12, 12, 6), "ICC_IGRPEN0"   },      // Interrupt Controller Interrupt Group 0 Enable (ICC_IGRPEN0) / Interrupt Controller Virtual Interrupt Group 0 Enable register (ICV_IGRPEN0)
	{ MakeOpHash(15, 0, 12, 12, 7), "ICC_IGRPEN1"   },      // Interrupt Controller Interrupt Group 1 Enable (ICC_IGRPEN1) / Interrupt Controller Virtual Interrupt Group 1 Enable register (ICV_IGRPEN1)
	{ MakeOpHash(15, 4, 12, 8, 0),  "ICH_AP0R0"     },      // Interrupt Controller Hyp Active Priorities Group 0 Register 0
	{ MakeOpHash(15, 4, 12, 8, 1),  "ICH_AP0R1"     },      // Interrupt Controller Hyp Active Priorities Group 0 Register 1
	{ MakeOpHash(15, 4, 12, 8, 2),  "ICH_AP0R2"     },      // Interrupt Controller Hyp Active Priorities Group 0 Register 2
	{ MakeOpHash(15, 4, 12, 8, 3),  "ICH_AP0R3"     },      // Interrupt Controller Hyp Active Priorities Group 0 Register 3
	{ MakeOpHash(15, 4, 12, 9, 0),  "ICH_AP1R0"     },      // Interrupt Controller Hyp Active Priorities Group 1 Register 0
	{ MakeOpHash(15, 4, 12, 9, 1),  "ICH_AP1R1"     },      // Interrupt Controller Hyp Active Priorities Group 1 Register 1
	{ MakeOpHash(15, 4, 12, 9, 2),  "ICH_AP1R2"     },      // Interrupt Controller Hyp Active Priorities Group 1 Register 2
	{ MakeOpHash(15, 4, 12, 9, 3),  "ICH_AP1R3"     },      // Interrupt Controller Hyp Active Priorities Group 1 Register 3
	{ MakeOpHash(15, 4, 12, 9, 5),  "ICC_HSRE"      },      // Interrupt Controller Hyp System Register Enable register
	{ MakeOpHash(15, 4, 12, 11, 0), "ICH_HCR"       },      // Interrupt Controller Hyp Control Register
	{ MakeOpHash(15, 4, 12, 11, 1), "ICH_VTR"       },      // Interrupt Controller VGIC Type Register
	{ MakeOpHash(15, 4, 12, 11, 2), "ICH_MISR"      },      // Interrupt Controller Maintenance Interrupt State Register
	{ MakeOpHash(15, 4, 12, 11, 3), "ICH_EISR"      },      // Interrupt Controller End of Interrupt Status Register
	{ MakeOpHash(15, 4, 12, 11, 5), "ICH_ELRSR"     },      // Interrupt Controller Empty List Register Status Register
	{ MakeOpHash(15, 4, 12, 11, 7), "ICH_VMCR"      },      // Interrupt Controller Virtual Machine Control Register
	{ MakeOpHash(15, 4, 12, 12, 0), "ICH_LR0"       },      // Interrupt Controller List Register 0
	{ MakeOpHash(15, 4, 12, 12, 1), "ICH_LR1"       },      // Interrupt Controller List Register 1
	{ MakeOpHash(15, 4, 12, 12, 2), "ICH_LR2"       },      // Interrupt Controller List Register 2
	{ MakeOpHash(15, 4, 12, 12, 3), "ICH_LR3"       },      // Interrupt Controller List Register 3
	{ MakeOpHash(15, 4, 12, 12, 4), "ICH_LR4"       },      // Interrupt Controller List Register 4
	{ MakeOpHash(15, 4, 12, 12, 5), "ICH_LR5"       },      // Interrupt Controller List Register 5
	{ MakeOpHash(15, 4, 12, 12, 6), "ICH_LR6"       },      // Interrupt Controller List Register 6
	{ MakeOpHash(15, 4, 12, 12, 7), "ICH_LR7"       },      // Interrupt Controller List Register 7
	{ MakeOpHash(15, 4, 12, 13, 0), "ICH_LR8"       },      // Interrupt Controller List Register 8
	{ MakeOpHash(15, 4, 12, 13, 1), "ICH_LR9"       },      // Interrupt Controller List Register 9
	{ MakeOpHash(15, 4, 12, 13, 2), "ICH_LR10"      },      // Interrupt Controller List Register 10
	{ MakeOpHash(15, 4, 12, 13, 3), "ICH_LR11"      },      // Interrupt Controller List Register 11
	{ MakeOpHash(15, 4, 12, 13, 4), "ICH_LR12"      },      // Interrupt Controller List Register 12
	{ MakeOpHash(15, 4, 12, 13, 5), "ICH_LR13"      },      // Interrupt Controller List Register 13
	{ MakeOpHash(15, 4, 12, 13, 6), "ICH_LR14"      },      // Interrupt Controller List Register 14
	{ MakeOpHash(15, 4, 12, 13, 7), "ICH_LR15"      },      // Interrupt Controller List Register 15
	{ MakeOpHash(15, 4, 12, 14, 0), "ICH_LRC0"      },      // Interrupt Controller List Register 0
	{ MakeOpHash(15, 4, 12, 14, 1), "ICH_LRC1"      },      // Interrupt Controller List Register 1
	{ MakeOpHash(15, 4, 12, 14, 2), "ICH_LRC2"      },      // Interrupt Controller List Register 2
	{ MakeOpHash(15, 4, 12, 14, 3), "ICH_LRC3"      },      // Interrupt Controller List Register 3
	{ MakeOpHash(15, 4, 12, 14, 4), "ICH_LRC4"      },      // Interrupt Controller List Register 4
	{ MakeOpHash(15, 4, 12, 14, 5), "ICH_LRC5"      },      // Interrupt Controller List Register 5
	{ MakeOpHash(15, 4, 12, 14, 6), "ICH_LRC6"      },      // Interrupt Controller List Register 6
	{ MakeOpHash(15, 4, 12, 14, 7), "ICH_LRC7"      },      // Interrupt Controller List Register 7
	{ MakeOpHash(15, 4, 12, 15, 0), "ICH_LRC8"      },      // Interrupt Controller List Register 8
	{ MakeOpHash(15, 4, 12, 15, 1), "ICH_LRC9"      },      // Interrupt Controller List Register 9
	{ MakeOpHash(15, 4, 12, 15, 2), "ICH_LRC10"     },      // Interrupt Controller List Register 10
	{ MakeOpHash(15, 4, 12, 15, 3), "ICH_LRC11"     },      // Interrupt Controller List Register 11
	{ MakeOpHash(15, 4, 12, 15, 4), "ICH_LRC12"     },      // Interrupt Controller List Register 12
	{ MakeOpHash(15, 4, 12, 15, 5), "ICH_LRC13"     },      // Interrupt Controller List Register 13
	{ MakeOpHash(15, 4, 12, 15, 6), "ICH_LRC14"     },      // Interrupt Controller List Register 14
	{ MakeOpHash(15, 4, 12, 15, 7), "ICH_LRC15"     },      // Interrupt Controller List Register 15
	{ MakeOpHash(15, 6, 12, 12, 4), "ICC_MCTLR"     },      // Interrupt Controller Monitor Control Register
	{ MakeOpHash(15, 6, 12, 12, 5), "ICC_MSRE"      },      // Interrupt Controller Monitor System Register Enable register
	{ MakeOpHash(15, 6, 12, 12, 7), "ICC_MGRPEN1"   },      // Interrupt Controller Monitor Interrupt Group 1 Enable register
	
	{ MakeOpHash(15, 0, 15, 0, 0),  "IL1Data0"      },      // Instruction L1 Data n Register
	{ MakeOpHash(15, 0, 15, 0, 1),  "IL1Data1"      },      // Instruction L1 Data n Register
	{ MakeOpHash(15, 0, 15, 0, 2),  "IL1Data2"      },      // Instruction L1 Data n Register
	{ MakeOpHash(15, 0, 15, 1, 0),  "DL1Data0"      },      // Data L1 Data n Register
	{ MakeOpHash(15, 0, 15, 1, 1),  "DL1Data1"      },      // Data L1 Data n Register
	{ MakeOpHash(15, 0, 15, 1, 2),  "DL1Data2"      },      // Data L1 Data n Register
	{ MakeOpHash(15, 0, 15, 2, 0),  "NA_DataMemRemap" },    // Data Memory Remap (ARM11)
	{ MakeOpHash(15, 0, 15, 2, 1),  "NA_InstMemRemap" },    // Instruction Memory Remap (ARM11)
	{ MakeOpHash(15, 0, 15, 2, 2),  "NA_DMAMemRemap" },     // DMA Memory Remap (ARM11)
	{ MakeOpHash(15, 0, 15, 2, 3),  "NA_PerifPortMemRemap" }, // Peripheral Port Memory Remap (ARM11)
	{ MakeOpHash(15, 0, 15, 4, 0),  "RAMINDEX"      },      // RAM Index Register
	{ MakeOpHash(15, 0, 15, 12, 0), "NA_PMonControl" },     // Performance Monitor Control (ARM11)
	{ MakeOpHash(15, 0, 15, 12, 1), "CCNT"          },      // Cycle Counter (ARM11)
	{ MakeOpHash(15, 0, 15, 12, 2), "PMN0"          },      // Count 0 (ARM11)
	{ MakeOpHash(15, 0, 15, 12, 3), "PMN1"          },      // Count 1 (ARM11)
	{ MakeOpHash(15, 1, 15, 0, 0),  "L2ACTLR"       },      // L2 Auxiliary Control Register
	{ MakeOpHash(15, 1, 15, 0, 3),  "L2FPR"         },      // L2 Prefetch Control Register
	{ MakeOpHash(15, 3, 15, 0, 0),  "NA_DDebugCache" },     // Data Debug Cache (ARM11)
	{ MakeOpHash(15, 3, 15, 0, 1),  "NA_IDebugCache" },     // Instruction Debug Cache (ARM11)
	{ MakeOpHash(15, 3, 15, 2, 0),  "NA_DTagRAMReadOp" },   // Data Tag RAM Read Operation (ARM11)
	{ MakeOpHash(15, 3, 15, 2, 1),  "NA_ITagRAMReadOp" },   // Instruction Tag RAM Read Operation (ARM11)
	{ MakeOpHash(15, 4, 15, 0, 0),  "CBAR"          },      // Configuration Base Address Register
	{ MakeOpHash(15, 5, 15, 4, 0),  "NA_DMicroTLBIdx" },    // Data MicroTLB Index (ARM11)
	{ MakeOpHash(15, 5, 15, 4, 1),  "NA_IMicroTLBIdx" },    // Instruction MicroTLB Index (ARM11)
	{ MakeOpHash(15, 5, 15, 4, 2),  "NA_ReadMainTLBEntry" }, // Read Main TLB Entry (ARM11)
	{ MakeOpHash(15, 5, 15, 4, 4),  "NA_WriteMainTLBEntry" }, // Write Main TLB Entry (ARM11)
	{ MakeOpHash(15, 5, 15, 5, 0),  "NA_DMicroTLBVA" },     // Data MicroTLB VA (ARM11)
	{ MakeOpHash(15, 5, 15, 5, 1),  "NA_IMicroTLBVA" },     // Instruction MicroTLB VA (ARM11)
	{ MakeOpHash(15, 5, 15, 5, 2),  "NA_MainTLBVA" },       // Main TLB VA (ARM11)
	{ MakeOpHash(15, 5, 15, 7, 0),  "NA_DMicroTLBAttr" },   // Data MicroTLB Attribute (ARM11)
	{ MakeOpHash(15, 5, 15, 7, 1),  "NA_IMicroTLBAttr" },   // Instruction MicroTLB Attribute (ARM11)
	{ MakeOpHash(15, 5, 15, 7, 2),  "NA_MainTLBAttr" },     // Main TLB Attribute (ARM11)
	{ MakeOpHash(15, 7, 15, 0, 0),  "NA_CacheDebugControl" }, // Cache Debug Control (ARM11)
	{ MakeOpHash(15, 7, 15, 1, 0),  "NA_TLBDebugControl" }, // TLB Debug Control (ARM11)

	{ MakeOpHash(15, 0, 15, 3, 2),  "NA_ReadITLBCAMinL1Data01" }, // Read I-TLB CAM into data L1 data 0/1 Register (Cortex-A8)
	{ MakeOpHash(15, 0, 15, 0, 3),  "NA_WriteDL1Data0toDTLBAttr" }, // Write D-L1 data 0 Register to D-TLB ATTR (Cortex-A8)
	{ MakeOpHash(15, 0, 15, 1, 3),  "NA_WriteIL1Data0toITLBAttr" }, // Write I-L1 data 0 Register to I-TLB ATTR (Cortex-A8)
	{ MakeOpHash(15, 0, 15, 3, 3),  "NA_ReadITLBATTRinL1Data0" }, // Read I-TLB ATTR into data L1 data 0 Register (Cortex-A8)
	{ MakeOpHash(15, 0, 15, 0, 4),  "NA_WriteDL1Data0toDTLBPA" }, // Write D-L1 data 0 Register to D-TLB PA (Cortex-A8)
	{ MakeOpHash(15, 0, 15, 2, 4),  "NA_ReadDTLBPAinL1Data0" }, // Read D-TLB PA into data L1 data 0 Register (Cortex-A8)
	{ MakeOpHash(15, 0, 15, 1, 4),  "NA_WriteIL1Data0toITLBPA" }, // Write I-L1 data 0 Register to I-TLB PA (Cortex-A8)
	{ MakeOpHash(15, 0, 15, 3, 4),  "NA_ReadITLBPAinL1Data0" }, // Read I-TLB PA into data L1 data 0 Register (Cortex-A8)

	{ MakeOpHash(15, 0, 8, 5, 3),  "NA_InvITLBSingleEntry" }, //  Invalidate Instruction TLB Single Entry on MVA only Register
	{ MakeOpHash(15, 0, 8, 6, 3),  "NA_InvDTLB" },           //  Invalidate Data TLB Register
	{ MakeOpHash(15, 5, 15, 6, 2), "NA_MainTLBAttr" },       //  Main TLB Attribute Register

	{ MakeOpHash(15, 3, 15, 2, 2), "NA_DTagRAMParityReadOp" }, // Data Tag RAM Parity Read Operation
	{ MakeOpHash(15, 3, 15, 2, 3), "NA_ICacheTagRAMParityReadOp" }, // Instruction cache Tag RAM Parity Read Operation
	{ MakeOpHash(15, 3, 15, 4, 1), "NA_ICacheDataRAMReadOp" }, // Instruction Cache Data RAM Read Operation
	{ MakeOpHash(15, 3, 15, 4, 2), "NA_DCacheDataRAMReadOp" }, // Data Cache Data RAM Parity Read Operation
	{ MakeOpHash(15, 3, 15, 4, 3), "NA_ICacheDataRAMParityReadOp" }, // Instruction Cache Data RAM Parity Read Operation	c15, Cache Data RAM parity read 
	{ MakeOpHash(15, 3, 15, 8, 0), "NA_ICacheMasterValid" }, // Instruction Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 8, 1), "NA_ICacheMasterValid" }, // Instruction Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 8, 2), "NA_ICacheMasterValid" }, // Instruction Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 8, 3), "NA_ICacheMasterValid" }, // Instruction Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 8, 4), "NA_ICacheMasterValid" }, // Instruction Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 8, 5), "NA_ICacheMasterValid" }, // Instruction Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 8, 6), "NA_ICacheMasterValid" }, // Instruction Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 8, 7), "NA_ICacheMasterValid" }, // Instruction Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 12, 0), "NA_DCacheMasterValid" }, //  Data Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 12, 1), "NA_DCacheMasterValid" }, //  Data Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 12, 2), "NA_DCacheMasterValid" }, //  Data Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 12, 3), "NA_DCacheMasterValid" }, //  Data Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 12, 4), "NA_DCacheMasterValid" }, //  Data Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 12, 5), "NA_DCacheMasterValid" }, //  Data Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 12, 6), "NA_DCacheMasterValid" }, //  Data Cache Master Valid Register
	{ MakeOpHash(15, 3, 15, 12, 7), "NA_DCacheMasterValid" }, //  Data Cache Master Valid Register
	{ MakeOpHash(15, 7, 15, 2, 0), "NA_DTagRAMOp" },      	// Data Tag RAM operation
	{ MakeOpHash(15, 7, 15, 2, 1), "NA_ICacheTagRAMOp" }, 	// Instruction cache Tag RAM operation
	{ MakeOpHash(15, 7, 15, 2, 2), "NA_DValidRAMnDirtyRAMOp" }, // Data Valid RAM and Dirty RAM operation
	{ MakeOpHash(15, 7, 15, 4, 1), "NA_ICacheDataRAM" },	// Instruction Cache Data RAM

	// Jazelle Registers
	{ MakeOpHash(14, 7, 0, 0, 0),   "JIDR"          },      // Jazelle ID Register
	{ MakeOpHash(14, 7, 1, 0, 0),   "JOSCR"         },      // Jazelle OS Control Register
	{ MakeOpHash(14, 7, 2, 0, 0),   "JMCR"          },      // Jazelle Main Configuration Register
	
	// Debug Registers
	{ MakeOpHash(15, 3, 4, 5, 0),   "DSPSR"         },      // Debug Saved Program Status Register (AArch32)
	{ MakeOpHash(15, 3, 4, 5, 1),   "DLR"           },      // Debug Link Register (AArch32)
	{ MakeOpHash(14, 0, 0, 0, 0),   "DBGDIDR"       },      // Debug ID Register
	{ MakeOpHash(14, 0, 0, 6, 0),   "DBGWFAR"       },      // Debug Watchpoint Fault Address Register
	{ MakeOpHash(14, 0, 0, 6, 2),   "DBGOSECCR"     },      // Debug OS Lock Exception Catch Control Register (AArch32)
	{ MakeOpHash(14, 0, 0, 7, 0),   "DBGVCR"        },      // Debug Vector Catch Register
	{ MakeOpHash(14, 0, 0, 9, 0),   "DBGECR"        },      // Debug Event Catch Register
	{ MakeOpHash(14, 0, 0, 10, 0),  "DBGDSCCR"      },      // Debug State Cache Control
	{ MakeOpHash(14, 0, 0, 11, 0),  "DBGDSMCR"      },      // Debug State MMU Control
	{ MakeOpHash(14, 0, 0, 0, 2),   "DBGDTRRXext"   },      // Debug OS Lock Data Transfer Register, Receive, External View
	{ MakeOpHash(14, 0, 0, 2, 0),   "DBGDCCINT"     },      // DCC Interrupt Enable Register (AArch32)
	{ MakeOpHash(14, 0, 0, 2, 2),   "DBGDSCRext"    },      // Debug Status and Control Register, External View
	{ MakeOpHash(14, 0, 0, 3, 2),   "DBGDTRTXext"   },      // Debug OS Lock Data Transfer Register, Transmit
	{ MakeOpHash(14, 0, 0, 4, 2),   "DBGDRCR"       },      // Debug Run Control
	{ MakeOpHash(14, 0, 0, 0, 4),   "DBGBVR0"       },      // Debug Breakpoint Value Register 0
	{ MakeOpHash(14, 0, 0, 1, 4),   "DBGBVR1"       },      // Debug Breakpoint Value Register 1
	{ MakeOpHash(14, 0, 0, 2, 4),   "DBGBVR2"       },      // Debug Breakpoint Value Register 2
	{ MakeOpHash(14, 0, 0, 3, 4),   "DBGBVR3"       },      // Debug Breakpoint Value Register 3
	{ MakeOpHash(14, 0, 0, 4, 4),   "DBGBVR4"       },      // Debug Breakpoint Value Register 4
	{ MakeOpHash(14, 0, 0, 5, 4),   "DBGBVR5"       },      // Debug Breakpoint Value Register 5
	{ MakeOpHash(14, 0, 0, 6, 4),   "DBGBVR6"       },      // Debug Breakpoint Value Register 6
	{ MakeOpHash(14, 0, 0, 7, 4),   "DBGBVR7"       },      // Debug Breakpoint Value Register 7
	{ MakeOpHash(14, 0, 0, 8, 4),   "DBGBVR8"       },      // Debug Breakpoint Value Register 8
	{ MakeOpHash(14, 0, 0, 9, 4),   "DBGBVR9"       },      // Debug Breakpoint Value Register 9
	{ MakeOpHash(14, 0, 0, 10, 4),  "DBGBVR10"      },      // Debug Breakpoint Value Register 10
	{ MakeOpHash(14, 0, 0, 11, 4),  "DBGBVR11"      },      // Debug Breakpoint Value Register 11
	{ MakeOpHash(14, 0, 0, 12, 4),  "DBGBVR12"      },      // Debug Breakpoint Value Register 12
	{ MakeOpHash(14, 0, 0, 13, 4),  "DBGBVR13"      },      // Debug Breakpoint Value Register 13
	{ MakeOpHash(14, 0, 0, 14, 4),  "DBGBVR14"      },      // Debug Breakpoint Value Register 14
	{ MakeOpHash(14, 0, 0, 15, 4),  "DBGBVR15"      },      // Debug Breakpoint Value Register 15
	{ MakeOpHash(14, 0, 0, 0, 5),   "DBGBCR0"       },      // Debug Breakpoint Control Register 0
	{ MakeOpHash(14, 0, 0, 1, 5),   "DBGBCR1"       },      // Debug Breakpoint Control Register 1
	{ MakeOpHash(14, 0, 0, 2, 5),   "DBGBCR2"       },      // Debug Breakpoint Control Register 2
	{ MakeOpHash(14, 0, 0, 3, 5),   "DBGBCR3"       },      // Debug Breakpoint Control Register 3
	{ MakeOpHash(14, 0, 0, 4, 5),   "DBGBCR4"       },      // Debug Breakpoint Control Register 4
	{ MakeOpHash(14, 0, 0, 5, 5),   "DBGBCR5"       },      // Debug Breakpoint Control Register 5
	{ MakeOpHash(14, 0, 0, 6, 5),   "DBGBCR6"       },      // Debug Breakpoint Control Register 6
	{ MakeOpHash(14, 0, 0, 7, 5),   "DBGBCR7"       },      // Debug Breakpoint Control Register 7
	{ MakeOpHash(14, 0, 0, 8, 5),   "DBGBCR8"       },      // Debug Breakpoint Control Register 8
	{ MakeOpHash(14, 0, 0, 9, 5),   "DBGBCR9"       },      // Debug Breakpoint Control Register 9
	{ MakeOpHash(14, 0, 0, 10, 5),  "DBGBCR10"      },      // Debug Breakpoint Control Register 10
	{ MakeOpHash(14, 0, 0, 11, 5),  "DBGBCR11"      },      // Debug Breakpoint Control Register 11
	{ MakeOpHash(14, 0, 0, 12, 5),  "DBGBCR12"      },      // Debug Breakpoint Control Register 12
	{ MakeOpHash(14, 0, 0, 13, 5),  "DBGBCR13"      },      // Debug Breakpoint Control Register 13
	{ MakeOpHash(14, 0, 0, 14, 5),  "DBGBCR14"      },      // Debug Breakpoint Control Register 14
	{ MakeOpHash(14, 0, 0, 15, 5),  "DBGBCR15"      },      // Debug Breakpoint Control Register 15
	{ MakeOpHash(14, 0, 0, 0, 6),   "DBGWVR0"       },      // Debug Watchpoint Value Register 0
	{ MakeOpHash(14, 0, 0, 1, 6),   "DBGWVR1"       },      // Debug Watchpoint Value Register 1
	{ MakeOpHash(14, 0, 0, 2, 6),   "DBGWVR2"       },      // Debug Watchpoint Value Register 2
	{ MakeOpHash(14, 0, 0, 3, 6),   "DBGWVR3"       },      // Debug Watchpoint Value Register 3
	{ MakeOpHash(14, 0, 0, 4, 6),   "DBGWVR4"       },      // Debug Watchpoint Value Register 4
	{ MakeOpHash(14, 0, 0, 5, 6),   "DBGWVR5"       },      // Debug Watchpoint Value Register 5
	{ MakeOpHash(14, 0, 0, 6, 6),   "DBGWVR6"       },      // Debug Watchpoint Value Register 6
	{ MakeOpHash(14, 0, 0, 7, 6),   "DBGWVR7"       },      // Debug Watchpoint Value Register 7
	{ MakeOpHash(14, 0, 0, 8, 6),   "DBGWVR8"       },      // Debug Watchpoint Value Register 8
	{ MakeOpHash(14, 0, 0, 9, 6),   "DBGWVR9"       },      // Debug Watchpoint Value Register 9
	{ MakeOpHash(14, 0, 0, 10, 6),  "DBGWVR10"      },      // Debug Watchpoint Value Register 10
	{ MakeOpHash(14, 0, 0, 11, 6),  "DBGWVR11"      },      // Debug Watchpoint Value Register 11
	{ MakeOpHash(14, 0, 0, 12, 6),  "DBGWVR12"      },      // Debug Watchpoint Value Register 12
	{ MakeOpHash(14, 0, 0, 13, 6),  "DBGWVR13"      },      // Debug Watchpoint Value Register 13
	{ MakeOpHash(14, 0, 0, 14, 6),  "DBGWVR14"      },      // Debug Watchpoint Value Register 14
	{ MakeOpHash(14, 0, 0, 15, 6),  "DBGWVR15"      },      // Debug Watchpoint Value Register 15
	{ MakeOpHash(14, 0, 0, 0, 7),   "DBGWCR0"       },      // Debug Watchpoint Control Register 0
	{ MakeOpHash(14, 0, 0, 1, 7),   "DBGWCR1"       },      // Debug Watchpoint Control Register 1
	{ MakeOpHash(14, 0, 0, 2, 7),   "DBGWCR2"       },      // Debug Watchpoint Control Register 2
	{ MakeOpHash(14, 0, 0, 3, 7),   "DBGWCR3"       },      // Debug Watchpoint Control Register 3
	{ MakeOpHash(14, 0, 0, 4, 7),   "DBGWCR4"       },      // Debug Watchpoint Control Register 4
	{ MakeOpHash(14, 0, 0, 5, 7),   "DBGWCR5"       },      // Debug Watchpoint Control Register 5
	{ MakeOpHash(14, 0, 0, 6, 7),   "DBGWCR6"       },      // Debug Watchpoint Control Register 6
	{ MakeOpHash(14, 0, 0, 7, 7),   "DBGWCR7"       },      // Debug Watchpoint Control Register 7
	{ MakeOpHash(14, 0, 0, 8, 7),   "DBGWCR8"       },      // Debug Watchpoint Control Register 8
	{ MakeOpHash(14, 0, 0, 9, 7),   "DBGWCR9"       },      // Debug Watchpoint Control Register 9
	{ MakeOpHash(14, 0, 0, 10, 7),  "DBGWCR10"      },      // Debug Watchpoint Control Register 10
	{ MakeOpHash(14, 0, 0, 11, 7),  "DBGWCR11"      },      // Debug Watchpoint Control Register 11
	{ MakeOpHash(14, 0, 0, 12, 7),  "DBGWCR12"      },      // Debug Watchpoint Control Register 12
	{ MakeOpHash(14, 0, 0, 13, 7),  "DBGWCR13"      },      // Debug Watchpoint Control Register 13
	{ MakeOpHash(14, 0, 0, 14, 7),  "DBGWCR14"      },      // Debug Watchpoint Control Register 14
	{ MakeOpHash(14, 0, 0, 15, 7),  "DBGWCR15"      },      // Debug Watchpoint Control Register 15
	{ MakeOpHash(14, 0, 1, 0, 1),   "DBGBXVR0"      },      // Debug Breakpoint Extended Value Register 0
	{ MakeOpHash(14, 0, 1, 1, 1),   "DBGBXVR1"      },      // Debug Breakpoint Extended Value Register 1
	{ MakeOpHash(14, 0, 1, 2, 1),   "DBGBXVR2"      },      // Debug Breakpoint Extended Value Register 2
	{ MakeOpHash(14, 0, 1, 3, 1),   "DBGBXVR3"      },      // Debug Breakpoint Extended Value Register 3
	{ MakeOpHash(14, 0, 1, 4, 1),   "DBGBXVR4"      },      // Debug Breakpoint Extended Value Register 4
	{ MakeOpHash(14, 0, 1, 5, 1),   "DBGBXVR5"      },      // Debug Breakpoint Extended Value Register 5
	{ MakeOpHash(14, 0, 1, 6, 1),   "DBGBXVR6"      },      // Debug Breakpoint Extended Value Register 6
	{ MakeOpHash(14, 0, 1, 7, 1),   "DBGBXVR7"      },      // Debug Breakpoint Extended Value Register 7
	{ MakeOpHash(14, 0, 1, 8, 1),   "DBGBXVR8"      },      // Debug Breakpoint Extended Value Register 8
	{ MakeOpHash(14, 0, 1, 9, 1),   "DBGBXVR9"      },      // Debug Breakpoint Extended Value Register 9
	{ MakeOpHash(14, 0, 1, 10, 1),  "DBGBXVR10"     },      // Debug Breakpoint Extended Value Register 10
	{ MakeOpHash(14, 0, 1, 11, 1),  "DBGBXVR11"     },      // Debug Breakpoint Extended Value Register 11
	{ MakeOpHash(14, 0, 1, 12, 1),  "DBGBXVR12"     },      // Debug Breakpoint Extended Value Register 12
	{ MakeOpHash(14, 0, 1, 13, 1),  "DBGBXVR13"     },      // Debug Breakpoint Extended Value Register 13
	{ MakeOpHash(14, 0, 1, 14, 1),  "DBGBXVR14"     },      // Debug Breakpoint Extended Value Register 14
	{ MakeOpHash(14, 0, 1, 15, 1),  "DBGBXVR15"     },      // Debug Breakpoint Extended Value Register 15
	{ MakeOpHash(14, 0, 1, 0, 4),   "DBGOSLAR"      },      // Debug OS Lock Access Register
	{ MakeOpHash(14, 0, 1, 1, 4),   "DBGOSLSR"      },      // Debug OS Lock Status Register
	{ MakeOpHash(14, 0, 1, 2, 4),   "DBGOSSRR"      },      // Debug OS Save and Restore
	{ MakeOpHash(14, 0, 1, 4, 4),   "DBGPRCR"       },      // Debug Power Control Register
	{ MakeOpHash(14, 0, 1, 5, 4),   "DBGPRSR"       },      // Debug Power Status Register
	{ MakeOpHash(14, 0, 7, 0, 4),   "DBGITCTRL"     },      // Debug Integration Mode Control
	{ MakeOpHash(14, 0, 7, 14, 6),  "DBGAUTHSTATUS" },      // Debug Authentication Status register
	{ MakeOpHash(14, 0, 7, 0, 7),   "DBGDEVID2"     },      // Debug Device ID register 2
	{ MakeOpHash(14, 0, 7, 1, 7),   "DBGDEVID1"     },      // Debug Device ID register 1
	{ MakeOpHash(14, 0, 7, 2, 7),   "DBGDEVID"      },      // Debug Device ID register 0
	{ MakeOpHash(14, 0, 7, 8, 6),   "DBGCLAIMSET"   },      // Debug Claim Tag Set register
	{ MakeOpHash(14, 0, 7, 9, 6),   "DBGCLAIMCLR"   },      // Debug Claim Tag Clear register
	{ MakeOpHash(14, 0, 0, 1, 0),   "DBGDSCRint"    },      // Debug Status and Control Register, Internal View
	{ MakeOpHash(14, 0, 0, 5, 0),   "DBGDTRRXint"   },      // Debug Data Transfer Register (DBGDTRRXint) / Debug Data Transfer Register, Transmit (DBGDTRTXint)
	{ MakeOpHash(14, 0, 1, 0, 0),   "DBGDRAR"       },      // Debug ROM Address Register
	{ MakeOpHash(14, 0, 1, 3, 4),   "DBGOSDLR"      },      // Debug OS Double Lock Register / OS Double Lock
	{ MakeOpHash(14, 0, 2, 0, 0),   "DBGDSAR"       },      // Debug Self Address Register
};

bool AArch32Extender::init()
{
	if (IDAAPI_IsBE()) {
		m_modeARM = cs_mode(CS_MODE_ARM | CS_MODE_BIG_ENDIAN);
		m_modeThumb = cs_mode(CS_MODE_THUMB | CS_MODE_BIG_ENDIAN);
	}
	else {
		m_modeARM = cs_mode(CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN);
		m_modeThumb = cs_mode(CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN);
	}
	if (cs_open(CS_ARCH_ARM, m_modeARM, &m_capstoneHandle) != CS_ERR_OK)
	{
		msg("[FRIEND]: failed to initialize capstone\n");
		return false;
	}
	
	cs_option(m_capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
	
	return true;
}

bool AArch32Extender::close()
{
	if (m_capstoneHandle != 0)
	{
		if (cs_close(&m_capstoneHandle) != CS_ERR_OK)
			return false;
	}
	
	return true;
}

bool AArch32Extender::output(uint16_t itype, ea_t address, uint32_t size, ProcOutput& procOutput)
{
	switch (itype)
	{
		case ARM_mcr:
		case ARM_mrc:
			return printMoveOutput(address, size, procOutput);
			
		default:
			break;
	}
	return false;
}

bool AArch32Extender::getSystemRegisterName(ea_t address, char* nameBuffer, uint32_t nameLength)
{
	bool ret = false;
	
	cs_insn *capstoneDisasm;
	cs_insn ci;
	uint8_t rawInstruction[4] = {0};
	size_t count = 0;
	uint32_t size = 0;
	
#if IDA_SDK_VERSION >= 700
	insn_t insn;
	decode_insn(&insn, address);
	size = insn.size;
#else
	decode_insn(address);
	size = cmd.size;
#endif
	
	BAIL_IF(IDAAPI_GetBytes(rawInstruction, size, address) == 0, "[FRIEND]: unable to read instruction at " PRINTF_ADDR "\n", address);
	
	if (isThumbArea(address))
		cs_option(m_capstoneHandle, CS_OPT_MODE, m_modeThumb);
	else
		cs_option(m_capstoneHandle, CS_OPT_MODE, m_modeARM);
	
	count = cs_disasm(m_capstoneHandle, rawInstruction, size, address, 1, &capstoneDisasm);
	BAIL_IF(count <= 0, "[FRIEND]: unable to decode instruction at " PRINTF_ADDR " [ %.2X%.2X%.2X%.2X ]\n",
			address, rawInstruction[0], rawInstruction[1], rawInstruction[2], rawInstruction[3]);
	
	ci = capstoneDisasm[0];
	
	if (ci.detail && ci.detail->arm.op_count > 4)
	{
		cs_arm_op* ops = ci.detail->arm.operands;
		
		uint32_t opHash = 0;
		if (ci.detail->arm.op_count == 6)
			opHash = MakeOpHash(ops[0].imm, ops[1].imm, ops[3].imm, ops[4].imm, ops[5].imm);
		else
			opHash = MakeOpHash(ops[0].imm, ops[1].imm, ops[3].imm, ops[4].imm);
		
		BAIL_IF(s_operandMap.find(opHash) == s_operandMap.end(), "[FRIEND]: unable to find register for instruction at " PRINTF_ADDR " [ %.2X%.2X%.2X%.2X ]\n",
				address, rawInstruction[0], rawInstruction[1], rawInstruction[2], rawInstruction[3]);
		
		auto cpRegName = s_operandMap[opHash];
		
		qstrncat(nameBuffer, SCOLOR_ON, nameLength);
		qstrncat(nameBuffer, SCOLOR_REG, nameLength);
		qstrncat(nameBuffer, cpRegName, nameLength);
		qstrncat(nameBuffer, SCOLOR_OFF, nameLength);
		qstrncat(nameBuffer, SCOLOR_REG, nameLength);
		
		qstrupr(nameBuffer);
	}

	ret = true;
		
bail:

	if (count > 0)
		cs_free(capstoneDisasm, 1);
	
	return ret;
}

bool AArch32Extender::isEnabled()
{
	return m_enabled;
}

bool AArch32Extender::setEnabled(bool enabled)
{
	m_enabled = enabled;
	return true;
}

bool AArch32Extender::isThumbArea(ea_t address)
{
	sel_t t = IDAAPI_GetSegmentReg(address, kRegT);
	return t != BADSEL && t != 0;
}

bool AArch32Extender::printMoveOutput(ea_t address, uint32_t size, ProcOutput& procOutput)
{
	bool ret = false;
	
	cs_insn *capstoneDisasm;
	cs_insn ci;
	uint8_t rawInstruction[4] = {0};
	std::string mnemonic;
	size_t count = 0;
	
	BAIL_IF(IDAAPI_GetBytes(rawInstruction, size, address) == 0, "[FRIEND]: unable to read instruction at " PRINTF_ADDR "\n", address);
	
	if (isThumbArea(address))
		cs_option(m_capstoneHandle, CS_OPT_MODE, m_modeThumb);
	else
		cs_option(m_capstoneHandle, CS_OPT_MODE, m_modeARM);
	
	count = cs_disasm(m_capstoneHandle, rawInstruction, size, address, 1, &capstoneDisasm);
	BAIL_IF(count <= 0, "[FRIEND]: unable to decode instruction at " PRINTF_ADDR " [ %.2X%.2X%.2X%.2X ]\n",
			address, rawInstruction[0], rawInstruction[1], rawInstruction[2], rawInstruction[3]);
	
	ci = capstoneDisasm[0];
	
	if (ci.detail && ci.detail->arm.op_count > 4)
	{
		cs_arm_op* ops = ci.detail->arm.operands;

		uint32_t opHash = 0;
		if (ci.detail->arm.op_count == 6)
			opHash = MakeOpHash(ops[0].imm, ops[1].imm, ops[3].imm, ops[4].imm, ops[5].imm);
		else
			opHash = MakeOpHash(ops[0].imm, ops[1].imm, ops[3].imm, ops[4].imm);
		
		BAIL_IF(s_operandMap.find(opHash) == s_operandMap.end(), "[FRIEND]: unable to find register for instruction at " PRINTF_ADDR " [ %.2X%.2X%.2X%.2X ]\n",
				address, rawInstruction[0], rawInstruction[1], rawInstruction[2], rawInstruction[3]);

		char regName[kMaxElementNameLength] = {0};
		qstrncpy(regName, cs_reg_name(m_capstoneHandle, ops[2].reg), sizeof(regName));
		
		std::string gpRegName(qstrupr(regName));
		std::string cpRegName(s_operandMap[opHash]);
		
		std::string operands("");
		
		if (ci.mnemonic[1] == 'R') // MRC
		{
			operands += SCOLOR_ON SCOLOR_REG + gpRegName + SCOLOR_OFF SCOLOR_REG;
			operands += ", ";
			operands += SCOLOR_ON SCOLOR_REG + cpRegName + SCOLOR_OFF SCOLOR_REG;
		}
		else // MCR
		{
			operands += SCOLOR_ON SCOLOR_REG + cpRegName + SCOLOR_OFF SCOLOR_REG;
			operands += ", ";
			operands += SCOLOR_ON SCOLOR_REG + gpRegName + SCOLOR_OFF SCOLOR_REG;
		}

		procOutput.init();
		
		mnemonic = (SCOLOR_ON SCOLOR_INSN + std::string(qstrupr(ci.mnemonic)) + SCOLOR_OFF SCOLOR_INSN);

		procOutput.printf("%-20s", mnemonic.c_str());
		procOutput.line(operands.c_str(), COLOR_UNAME);
		
		procOutput.flush();
		
		ret = true;
	}
	
bail:

	if (count > 0)
		cs_free(capstoneDisasm, 1);
	
	return ret;
}
