/*
 * QEMU e1000 emulation
 *
 * Software developer's manual:
 * http://download.intel.com/design/network/manuals/8254x_GBe_SDM.pdf
 *
 * Nir Peleg, Tutis Systems Ltd. for Qumranet Inc.
 * Copyright (c) 2008 Qumranet
 * Based on work done by:
 * Copyright (c) 2007 Dan Aloni
 * Copyright (c) 2004 Antony T Curtis
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */


#include "hw/hw.h"
#include "hw/pci/pci.h"
#include "net/net.h"
#include "net/checksum.h"
#include "hw/loader.h"
#include "sysemu/sysemu.h"
#include "sysemu/dma.h"
#include "qemu/iov.h"
#include "qemu/range.h"
#include "qom/cpu.h"

#include "bcm5709.h"

#define E1000_DEBUG

#ifdef E1000_DEBUG
enum {
    DEBUG_GENERAL,	DEBUG_IO,	DEBUG_MMIO,	DEBUG_INTERRUPT,
    DEBUG_RX,		DEBUG_TX,	DEBUG_MDIC,	DEBUG_EEPROM,
    DEBUG_UNKNOWN,	DEBUG_TXSUM,	DEBUG_TXERR,	DEBUG_RXERR,
    DEBUG_RXFILTER,     DEBUG_PHY,      DEBUG_NOTYET,
};
#define DBGBIT(x)	(1<<DEBUG_##x)
static int debugflags = 0xffffffff; //DBGBIT(TXERR) | DBGBIT(GENERAL);

#define	DBGOUT(what, fmt, ...) do { \
    if (debugflags & DBGBIT(what)) \
        fprintf(stderr, "bcm5709: " fmt, ## __VA_ARGS__); \
    } while (0)
#else
#define	DBGOUT(what, fmt, ...) do {} while (0)
#endif

#define IOPORT_SIZE       0x40
#define PNPMMIO_SIZE      0x2000000
#define MIN_BUF_SIZE      60 /* Min. octets in an ethernet frame sans FCS */

/* this is the size past which hardware will drop packets when setting LPE=0 */
#define MAXIMUM_ETHERNET_VLAN_SIZE 1522
/* this is the size past which hardware will drop packets when setting LPE=1 */
#define MAXIMUM_ETHERNET_LPE_SIZE 16384

#define MAXIMUM_ETHERNET_HDR_LEN (14+4)

/*
 * HW models:
 *  E1000_DEV_ID_82540EM works with Windows, Linux, and OS X <= 10.8
 *  E1000_DEV_ID_82544GC_COPPER appears to work; not well tested
 *  E1000_DEV_ID_82545EM_COPPER works with Linux and OS X >= 10.6
 *  Others never tested
 */

typedef struct E1000State_st {
    /*< private >*/
    PCIDevice parent_obj;
    /*< public >*/

    NICState *nic;
    NICConf conf;
    MemoryRegion mmio;
    MemoryRegion io;

    uint32_t mac_reg[0x8000];
    uint16_t phy_reg[0x20];
    uint16_t eeprom_data[64];

    uint32_t bnx2_nvram_off;
    uint8_t bnx2_nvram[65536];
    uint32_t rv2p_hi;
    uint32_t rv2p_lo;
    FILE *fp[8];

    uint32_t cpu_txp[10];
    uint32_t cpu_rxp[10];
    uint32_t cpu_tpat[10];
    uint32_t cpu_com[10];
    uint32_t cpu_cp[10];

    uint32_t rxbuf_size;
    uint32_t rxbuf_min_shift;
    struct e1000_tx {
        unsigned char header[256];
        unsigned char vlan_header[4];
        /* Fields vlan and data must not be reordered or separated. */
        unsigned char vlan[4];
        unsigned char data[0x10000];
        uint16_t size;
        unsigned char sum_needed;
        unsigned char vlan_needed;
        uint8_t ipcss;
        uint8_t ipcso;
        uint16_t ipcse;
        uint8_t tucss;
        uint8_t tucso;
        uint16_t tucse;
        uint8_t hdr_len;
        uint16_t mss;
        uint32_t paylen;
        uint16_t tso_frames;
        char tse;
        int8_t ip;
        int8_t tcp;
        char cptse;     // current packet tse bit
    } tx;

    struct {
        uint32_t val_in;	// shifted in from guest driver
        uint16_t bitnum_in;
        uint16_t bitnum_out;
        uint16_t reading;
        uint32_t old_eecd;
    } eecd_state;

    QEMUTimer *autoneg_timer;

    QEMUTimer *mit_timer;      /* Mitigation timer. */
    bool mit_timer_on;         /* Mitigation timer is running. */
    bool mit_irq_level;        /* Tracks interrupt pin level. */
    uint32_t mit_ide;          /* Tracks E1000_TXD_CMD_IDE bit. */

/* Compatibility flags for migration to/from qemu 1.3.0 and older */
#define E1000_FLAG_AUTONEG_BIT 0
#define E1000_FLAG_MIT_BIT 1
#define E1000_FLAG_AUTONEG (1 << E1000_FLAG_AUTONEG_BIT)
#define E1000_FLAG_MIT (1 << E1000_FLAG_MIT_BIT)
    uint32_t compat_flags;
} E1000State;

typedef struct E1000BaseClass {
    PCIDeviceClass parent_class;
    uint16_t phy_id2;
} E1000BaseClass;

#define TYPE_E1000_BASE "bcm5709-base"

#define E1000(obj) \
    OBJECT_CHECK(E1000State, (obj), TYPE_E1000_BASE)

#define E1000_DEVICE_CLASS(klass) \
     OBJECT_CLASS_CHECK(E1000BaseClass, (klass), TYPE_E1000_BASE)
#define E1000_DEVICE_GET_CLASS(obj) \
    OBJECT_GET_CLASS(E1000BaseClass, (obj), TYPE_E1000_BASE)

#define	defreg(x)	x = (E1000_##x>>2)
enum {
    defreg(CTRL),	defreg(EECD),	defreg(EERD),	defreg(GPRC),
    defreg(GPTC),	defreg(ICR),	defreg(ICS),	defreg(IMC),
    defreg(IMS),	defreg(LEDCTL),	defreg(MANC),	defreg(MDIC),
    defreg(MPC),	defreg(PBA),	defreg(RCTL),	defreg(RDBAH),
    defreg(RDBAL),	defreg(RDH),	defreg(RDLEN),	defreg(RDT),
    defreg(STATUS),	defreg(SWSM),	defreg(TCTL),	defreg(TDBAH),
    defreg(TDBAL),	defreg(TDH),	defreg(TDLEN),	defreg(TDT),
    defreg(TORH),	defreg(TORL),	defreg(TOTH),	defreg(TOTL),
    defreg(TPR),	defreg(TPT),	defreg(TXDCTL),	defreg(WUFC),
    defreg(RA),		defreg(MTA),	defreg(CRCERRS),defreg(VFTA),
    defreg(VET),        defreg(RDTR),   defreg(RADV),   defreg(TADV),
    defreg(ITR),
};

static void
e1000_link_down(E1000State *s)
{
    s->mac_reg[STATUS] &= ~E1000_STATUS_LU;
    s->phy_reg[PHY_STATUS] &= ~MII_SR_LINK_STATUS;
    s->phy_reg[PHY_STATUS] &= ~MII_SR_AUTONEG_COMPLETE;
    s->phy_reg[PHY_LP_ABILITY] &= ~MII_LPAR_LPACK;
}

static void
e1000_link_up(E1000State *s)
{
    s->mac_reg[STATUS] |= E1000_STATUS_LU;
    s->phy_reg[PHY_STATUS] |= MII_SR_LINK_STATUS;
}

static bool
have_autoneg(E1000State *s)
{
    return (s->compat_flags & E1000_FLAG_AUTONEG) &&
           (s->phy_reg[PHY_CTRL] & MII_CR_AUTO_NEG_EN);
}

static void
set_phy_ctrl(E1000State *s, int index, uint16_t val)
{
    /* bits 0-5 reserved; MII_CR_[RESTART_AUTO_NEG,RESET] are self clearing */
    s->phy_reg[PHY_CTRL] = val & ~(0x3f |
                                   MII_CR_RESET |
                                   MII_CR_RESTART_AUTO_NEG);

    /*
     * QEMU 1.3 does not support link auto-negotiation emulation, so if we
     * migrate during auto negotiation, after migration the link will be
     * down.
     */
    if (have_autoneg(s) && (val & MII_CR_RESTART_AUTO_NEG)) {
        e1000_link_down(s);
        DBGOUT(PHY, "Start link auto negotiation\n");
        timer_mod(s->autoneg_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 500);
    }
}

static void (*phyreg_writeops[])(E1000State *, int, uint16_t) = {
    [PHY_CTRL] = set_phy_ctrl,
};

enum { NPHYWRITEOPS = ARRAY_SIZE(phyreg_writeops) };

enum { PHY_R = 1, PHY_W = 2, PHY_RW = PHY_R | PHY_W };
static const char phy_regcap[0x20] = {
    [PHY_STATUS] = PHY_R,	[M88E1000_EXT_PHY_SPEC_CTRL] = PHY_RW,
    [PHY_ID1] = PHY_R,		[M88E1000_PHY_SPEC_CTRL] = PHY_RW,
    [PHY_CTRL] = PHY_RW,	[PHY_1000T_CTRL] = PHY_RW,
    [PHY_LP_ABILITY] = PHY_R,	[PHY_1000T_STATUS] = PHY_R,
    [PHY_AUTONEG_ADV] = PHY_RW,	[M88E1000_RX_ERR_CNTR] = PHY_R,
    [PHY_ID2] = PHY_R,		[M88E1000_PHY_SPEC_STATUS] = PHY_R,
    [PHY_AUTONEG_EXP] = PHY_R,
};

/* PHY_ID2 documented in 8254x_GBe_SDM.pdf, pp. 250 */
static const uint16_t phy_reg_init[] = {
    [PHY_CTRL] =   MII_CR_SPEED_SELECT_MSB |
                   MII_CR_FULL_DUPLEX |
                   MII_CR_AUTO_NEG_EN,

    [PHY_STATUS] = MII_SR_EXTENDED_CAPS |
                   MII_SR_LINK_STATUS |   /* link initially up */
                   MII_SR_AUTONEG_CAPS |
                   /* MII_SR_AUTONEG_COMPLETE: initially NOT completed */
                   MII_SR_PREAMBLE_SUPPRESS |
                   MII_SR_EXTENDED_STATUS |
                   MII_SR_10T_HD_CAPS |
                   MII_SR_10T_FD_CAPS |
                   MII_SR_100X_HD_CAPS |
                   MII_SR_100X_FD_CAPS,

    [PHY_ID1] = 0x141,
    /* [PHY_ID2] configured per DevId, from e1000_reset() */
    [PHY_AUTONEG_ADV] = 0xde1,
    [PHY_LP_ABILITY] = 0x1e0,
    [PHY_1000T_CTRL] = 0x0e00,
    [PHY_1000T_STATUS] = 0x3c00,
    [M88E1000_PHY_SPEC_CTRL] = 0x360,
    [M88E1000_PHY_SPEC_STATUS] = 0xac00,
    [M88E1000_EXT_PHY_SPEC_CTRL] = 0x0d60,
};

static const uint32_t mac_reg_init[] = {
    [PBA] =     0x00100030,
    [LEDCTL] =  0x602,
    [CTRL] =    E1000_CTRL_SWDPIN2 | E1000_CTRL_SWDPIN0 |
                E1000_CTRL_SPD_1000 | E1000_CTRL_SLU,
    [STATUS] =  0x80000000 | E1000_STATUS_GIO_MASTER_ENABLE |
                E1000_STATUS_ASDV | E1000_STATUS_MTXCKOK |
                E1000_STATUS_SPEED_1000 | E1000_STATUS_FD |
                E1000_STATUS_LU,
    [MANC] =    E1000_MANC_EN_MNG2HOST | E1000_MANC_RCV_TCO_EN |
                E1000_MANC_ARP_EN | E1000_MANC_0298_EN |
                E1000_MANC_RMCP_EN,
};

/* Helper function, *curr == 0 means the value is not set */
static inline void
mit_update_delay(uint32_t *curr, uint32_t value)
{
    if (value && (*curr == 0 || value < *curr)) {
        *curr = value;
    }
}

static void
set_interrupt_cause(E1000State *s, int index, uint32_t val)
{
    PCIDevice *d = PCI_DEVICE(s);
    uint32_t pending_ints;
    uint32_t mit_delay;

    s->mac_reg[ICR] = val;

    /*
     * Make sure ICR and ICS registers have the same value.
     * The spec says that the ICS register is write-only.  However in practice,
     * on real hardware ICS is readable, and for reads it has the same value as
     * ICR (except that ICS does not have the clear on read behaviour of ICR).
     *
     * The VxWorks PRO/1000 driver uses this behaviour.
     */
    s->mac_reg[ICS] = val;

    pending_ints = (s->mac_reg[IMS] & s->mac_reg[ICR]);
    if (!s->mit_irq_level && pending_ints) {
        /*
         * Here we detect a potential raising edge. We postpone raising the
         * interrupt line if we are inside the mitigation delay window
         * (s->mit_timer_on == 1).
         * We provide a partial implementation of interrupt mitigation,
         * emulating only RADV, TADV and ITR (lower 16 bits, 1024ns units for
         * RADV and TADV, 256ns units for ITR). RDTR is only used to enable
         * RADV; relative timers based on TIDV and RDTR are not implemented.
         */
        if (s->mit_timer_on) {
            return;
        }
        if (s->compat_flags & E1000_FLAG_MIT) {
            /* Compute the next mitigation delay according to pending
             * interrupts and the current values of RADV (provided
             * RDTR!=0), TADV and ITR.
             * Then rearm the timer.
             */
            mit_delay = 0;
            if (s->mit_ide &&
                    (pending_ints & (E1000_ICR_TXQE | E1000_ICR_TXDW))) {
                mit_update_delay(&mit_delay, s->mac_reg[TADV] * 4);
            }
            if (s->mac_reg[RDTR] && (pending_ints & E1000_ICS_RXT0)) {
                mit_update_delay(&mit_delay, s->mac_reg[RADV] * 4);
            }
            mit_update_delay(&mit_delay, s->mac_reg[ITR]);

            if (mit_delay) {
                s->mit_timer_on = 1;
                timer_mod(s->mit_timer, qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) +
                          mit_delay * 256);
            }
            s->mit_ide = 0;
        }
    }

    s->mit_irq_level = (pending_ints != 0);
    pci_set_irq(d, s->mit_irq_level);
}

static void
e1000_mit_timer(void *opaque)
{
    E1000State *s = opaque;

    s->mit_timer_on = 0;
    /* Call set_interrupt_cause to update the irq level (if necessary). */
    set_interrupt_cause(s, 0, s->mac_reg[ICR]);
}

static void
set_ics(E1000State *s, int index, uint32_t val)
{
    DBGOUT(INTERRUPT, "set_ics %x, ICR %x, IMR %x\n", val, s->mac_reg[ICR],
        s->mac_reg[IMS]);
    set_interrupt_cause(s, 0, val | s->mac_reg[ICR]);
    if (val == 4) {
        int i;
        for (i=0; i<8; i++)
            fclose(s->fp[i]);
    }
}

static void
e1000_autoneg_timer(void *opaque)
{
    E1000State *s = opaque;
    if (!qemu_get_queue(s->nic)->link_down) {
        e1000_link_up(s);
        s->phy_reg[PHY_LP_ABILITY] |= MII_LPAR_LPACK;
        s->phy_reg[PHY_STATUS] |= MII_SR_AUTONEG_COMPLETE;
        DBGOUT(PHY, "Auto negotiation is completed\n");
        set_ics(s, 0, E1000_ICS_LSC); /* signal link status change to guest */
    }
}

static int
rxbufsize(uint32_t v)
{
    v &= E1000_RCTL_BSEX | E1000_RCTL_SZ_16384 | E1000_RCTL_SZ_8192 |
         E1000_RCTL_SZ_4096 | E1000_RCTL_SZ_2048 | E1000_RCTL_SZ_1024 |
         E1000_RCTL_SZ_512 | E1000_RCTL_SZ_256;
    switch (v) {
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_16384:
        return 16384;
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_8192:
        return 8192;
    case E1000_RCTL_BSEX | E1000_RCTL_SZ_4096:
        return 4096;
    case E1000_RCTL_SZ_1024:
        return 1024;
    case E1000_RCTL_SZ_512:
        return 512;
    case E1000_RCTL_SZ_256:
        return 256;
    }
    return 2048;
}

static void e1000_reset(void *opaque)
{
    E1000State *d = opaque;
    E1000BaseClass *edc = E1000_DEVICE_GET_CLASS(d);
    uint8_t *macaddr = d->conf.macaddr.a;
    int i;

    timer_del(d->autoneg_timer);
    timer_del(d->mit_timer);
    d->mit_timer_on = 0;
    d->mit_irq_level = 0;
    d->mit_ide = 0;
    memset(d->phy_reg, 0, sizeof d->phy_reg);
    memmove(d->phy_reg, phy_reg_init, sizeof phy_reg_init);
    d->phy_reg[PHY_ID2] = edc->phy_id2;
    memset(d->mac_reg, 0, sizeof d->mac_reg);
    memmove(d->mac_reg, mac_reg_init, sizeof mac_reg_init);
    d->rxbuf_min_shift = 1;
    memset(&d->tx, 0, sizeof d->tx);

    if (qemu_get_queue(d->nic)->link_down) {
        e1000_link_down(d);
    }

    /* Some guests expect pre-initialized RAH/RAL (AddrValid flag + MACaddr) */
    d->mac_reg[RA] = 0;
    d->mac_reg[RA + 1] = E1000_RAH_AV;
    for (i = 0; i < 4; i++) {
        d->mac_reg[RA] |= macaddr[i] << (8 * i);
        d->mac_reg[RA + 1] |= (i < 2) ? macaddr[i + 4] << (8 * i) : 0;
    }
    qemu_format_nic_info_str(qemu_get_queue(d->nic), macaddr);
}

static void
set_ctrl(E1000State *s, int index, uint32_t val)
{
    /* RST is self clearing */
    s->mac_reg[CTRL] = val & ~E1000_CTRL_RST;
}

static void
set_rx_control(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[RCTL] = val;
    s->rxbuf_size = rxbufsize(val);
    s->rxbuf_min_shift = ((val / E1000_RCTL_RDMTS_QUAT) & 3) + 1;
    DBGOUT(RX, "RCTL: %d, mac_reg[RCTL] = 0x%x\n", s->mac_reg[RDT],
           s->mac_reg[RCTL]);
    qemu_flush_queued_packets(qemu_get_queue(s->nic));
}

static void
set_mdic(E1000State *s, int index, uint32_t val)
{
    uint32_t data = val & E1000_MDIC_DATA_MASK;
    uint32_t addr = ((val & E1000_MDIC_REG_MASK) >> E1000_MDIC_REG_SHIFT);

    if ((val & E1000_MDIC_PHY_MASK) >> E1000_MDIC_PHY_SHIFT != 1) // phy #
        val = s->mac_reg[MDIC] | E1000_MDIC_ERROR;
    else if (val & E1000_MDIC_OP_READ) {
        DBGOUT(MDIC, "MDIC read reg 0x%x\n", addr);
        if (!(phy_regcap[addr] & PHY_R)) {
            DBGOUT(MDIC, "MDIC read reg %x unhandled\n", addr);
            val |= E1000_MDIC_ERROR;
        } else
            val = (val ^ data) | s->phy_reg[addr];
    } else if (val & E1000_MDIC_OP_WRITE) {
        DBGOUT(MDIC, "MDIC write reg 0x%x, value 0x%x\n", addr, data);
        if (!(phy_regcap[addr] & PHY_W)) {
            DBGOUT(MDIC, "MDIC write reg %x unhandled\n", addr);
            val |= E1000_MDIC_ERROR;
        } else {
            if (addr < NPHYWRITEOPS && phyreg_writeops[addr]) {
                phyreg_writeops[addr](s, index, data);
            } else {
                s->phy_reg[addr] = data;
            }
        }
    }
    s->mac_reg[MDIC] = val | E1000_MDIC_READY;

    if (val & E1000_MDIC_INT_EN) {
        set_ics(s, 0, E1000_ICR_MDAC);
    }
}

static uint32_t
get_eecd(E1000State *s, int index)
{
    uint32_t ret = E1000_EECD_PRES|E1000_EECD_GNT | s->eecd_state.old_eecd;

    DBGOUT(EEPROM, "reading eeprom bit %d (reading %d)\n",
           s->eecd_state.bitnum_out, s->eecd_state.reading);
    if (!s->eecd_state.reading ||
        ((s->eeprom_data[(s->eecd_state.bitnum_out >> 4) & 0x3f] >>
          ((s->eecd_state.bitnum_out & 0xf) ^ 0xf))) & 1)
        ret |= E1000_EECD_DO;
    return ret;
}

static void
set_eecd(E1000State *s, int index, uint32_t val)
{
    uint32_t oldval = s->eecd_state.old_eecd;

    s->eecd_state.old_eecd = val & (E1000_EECD_SK | E1000_EECD_CS |
            E1000_EECD_DI|E1000_EECD_FWE_MASK|E1000_EECD_REQ);
    if (!(E1000_EECD_CS & val))			// CS inactive; nothing to do
	return;
    if (E1000_EECD_CS & (val ^ oldval)) {	// CS rise edge; reset state
	s->eecd_state.val_in = 0;
	s->eecd_state.bitnum_in = 0;
	s->eecd_state.bitnum_out = 0;
	s->eecd_state.reading = 0;
    }
    if (!(E1000_EECD_SK & (val ^ oldval)))	// no clock edge
        return;
    if (!(E1000_EECD_SK & val)) {		// falling edge
        s->eecd_state.bitnum_out++;
        return;
    }
    s->eecd_state.val_in <<= 1;
    if (val & E1000_EECD_DI)
        s->eecd_state.val_in |= 1;
    if (++s->eecd_state.bitnum_in == 9 && !s->eecd_state.reading) {
        s->eecd_state.bitnum_out = ((s->eecd_state.val_in & 0x3f)<<4)-1;
        s->eecd_state.reading = (((s->eecd_state.val_in >> 6) & 7) ==
            EEPROM_READ_OPCODE_MICROWIRE);
    }
    DBGOUT(EEPROM, "eeprom bitnum in %d out %d, reading %d\n",
           s->eecd_state.bitnum_in, s->eecd_state.bitnum_out,
           s->eecd_state.reading);
}

static uint32_t
flash_eerd_read(E1000State *s, int x)
{
    unsigned int index, r = s->mac_reg[EERD] & ~E1000_EEPROM_RW_REG_START;

    if ((s->mac_reg[EERD] & E1000_EEPROM_RW_REG_START) == 0)
        return (s->mac_reg[EERD]);

    if ((index = r >> E1000_EEPROM_RW_ADDR_SHIFT) > EEPROM_CHECKSUM_REG)
        return (E1000_EEPROM_RW_REG_DONE | r);

    return ((s->eeprom_data[index] << E1000_EEPROM_RW_REG_DATA) |
           E1000_EEPROM_RW_REG_DONE | r);
}

static void
putsum(uint8_t *data, uint32_t n, uint32_t sloc, uint32_t css, uint32_t cse)
{
    uint32_t sum;

    if (cse && cse < n)
        n = cse + 1;
    if (sloc < n-1) {
        sum = net_checksum_add(n-css, data+css);
        stw_be_p(data + sloc, net_checksum_finish(sum));
    }
}

static inline int
vlan_enabled(E1000State *s)
{
    return ((s->mac_reg[CTRL] & E1000_CTRL_VME) != 0);
}

static inline int
vlan_rx_filter_enabled(E1000State *s)
{
    return ((s->mac_reg[RCTL] & E1000_RCTL_VFE) != 0);
}

static inline int
is_vlan_packet(E1000State *s, const uint8_t *buf)
{
    return (be16_to_cpup((uint16_t *)(buf + 12)) ==
                le16_to_cpup((uint16_t *)(s->mac_reg + VET)));
}

static inline int
is_vlan_txd(uint32_t txd_lower)
{
    return ((txd_lower & E1000_TXD_CMD_VLE) != 0);
}

/* FCS aka Ethernet CRC-32. We don't get it from backends and can't
 * fill it in, just pad descriptor length by 4 bytes unless guest
 * told us to strip it off the packet. */
static inline int
fcs_len(E1000State *s)
{
    return (s->mac_reg[RCTL] & E1000_RCTL_SECRC) ? 0 : 4;
}

static void
e1000_send_packet(E1000State *s, const uint8_t *buf, int size)
{
    NetClientState *nc = qemu_get_queue(s->nic);
    if (s->phy_reg[PHY_CTRL] & MII_CR_LOOPBACK) {
        nc->info->receive(nc, buf, size);
    } else {
        qemu_send_packet(nc, buf, size);
    }
}

static void
xmit_seg(E1000State *s)
{
    uint16_t len, *sp;
    unsigned int frames = s->tx.tso_frames, css, sofar, n;
    struct e1000_tx *tp = &s->tx;

    if (tp->tse && tp->cptse) {
        css = tp->ipcss;
        DBGOUT(TXSUM, "frames %d size %d ipcss %d\n",
               frames, tp->size, css);
        if (tp->ip) {		// IPv4
            stw_be_p(tp->data+css+2, tp->size - css);
            stw_be_p(tp->data+css+4,
                          be16_to_cpup((uint16_t *)(tp->data+css+4))+frames);
        } else			// IPv6
            stw_be_p(tp->data+css+4, tp->size - css);
        css = tp->tucss;
        len = tp->size - css;
        DBGOUT(TXSUM, "tcp %d tucss %d len %d\n", tp->tcp, css, len);
        if (tp->tcp) {
            sofar = frames * tp->mss;
            stl_be_p(tp->data+css+4, ldl_be_p(tp->data+css+4)+sofar); /* seq */
            if (tp->paylen - sofar > tp->mss)
                tp->data[css + 13] &= ~9;		// PSH, FIN
        } else	// UDP
            stw_be_p(tp->data+css+4, len);
        if (tp->sum_needed & E1000_TXD_POPTS_TXSM) {
            unsigned int phsum;
            // add pseudo-header length before checksum calculation
            sp = (uint16_t *)(tp->data + tp->tucso);
            phsum = be16_to_cpup(sp) + len;
            phsum = (phsum >> 16) + (phsum & 0xffff);
            stw_be_p(sp, phsum);
        }
        tp->tso_frames++;
    }

    if (tp->sum_needed & E1000_TXD_POPTS_TXSM)
        putsum(tp->data, tp->size, tp->tucso, tp->tucss, tp->tucse);
    if (tp->sum_needed & E1000_TXD_POPTS_IXSM)
        putsum(tp->data, tp->size, tp->ipcso, tp->ipcss, tp->ipcse);
    if (tp->vlan_needed) {
        memmove(tp->vlan, tp->data, 4);
        memmove(tp->data, tp->data + 4, 8);
        memcpy(tp->data + 8, tp->vlan_header, 4);
        e1000_send_packet(s, tp->vlan, tp->size + 4);
    } else
        e1000_send_packet(s, tp->data, tp->size);
    s->mac_reg[TPT]++;
    s->mac_reg[GPTC]++;
    n = s->mac_reg[TOTL];
    if ((s->mac_reg[TOTL] += s->tx.size) < n)
        s->mac_reg[TOTH]++;
}

static void
process_tx_desc(E1000State *s, struct e1000_tx_desc *dp)
{
    PCIDevice *d = PCI_DEVICE(s);
    uint32_t txd_lower = le32_to_cpu(dp->lower.data);
    uint32_t dtype = txd_lower & (E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D);
    unsigned int split_size = txd_lower & 0xffff, bytes, sz, op;
    unsigned int msh = 0xfffff;
    uint64_t addr;
    struct e1000_context_desc *xp = (struct e1000_context_desc *)dp;
    struct e1000_tx *tp = &s->tx;

    s->mit_ide |= (txd_lower & E1000_TXD_CMD_IDE);
    if (dtype == E1000_TXD_CMD_DEXT) {	// context descriptor
        op = le32_to_cpu(xp->cmd_and_length);
        tp->ipcss = xp->lower_setup.ip_fields.ipcss;
        tp->ipcso = xp->lower_setup.ip_fields.ipcso;
        tp->ipcse = le16_to_cpu(xp->lower_setup.ip_fields.ipcse);
        tp->tucss = xp->upper_setup.tcp_fields.tucss;
        tp->tucso = xp->upper_setup.tcp_fields.tucso;
        tp->tucse = le16_to_cpu(xp->upper_setup.tcp_fields.tucse);
        tp->paylen = op & 0xfffff;
        tp->hdr_len = xp->tcp_seg_setup.fields.hdr_len;
        tp->mss = le16_to_cpu(xp->tcp_seg_setup.fields.mss);
        tp->ip = (op & E1000_TXD_CMD_IP) ? 1 : 0;
        tp->tcp = (op & E1000_TXD_CMD_TCP) ? 1 : 0;
        tp->tse = (op & E1000_TXD_CMD_TSE) ? 1 : 0;
        tp->tso_frames = 0;
        if (tp->tucso == 0) {	// this is probably wrong
            DBGOUT(TXSUM, "TCP/UDP: cso 0!\n");
            tp->tucso = tp->tucss + (tp->tcp ? 16 : 6);
        }
        return;
    } else if (dtype == (E1000_TXD_CMD_DEXT | E1000_TXD_DTYP_D)) {
        // data descriptor
        if (tp->size == 0) {
            tp->sum_needed = le32_to_cpu(dp->upper.data) >> 8;
        }
        tp->cptse = ( txd_lower & E1000_TXD_CMD_TSE ) ? 1 : 0;
    } else {
        // legacy descriptor
        tp->cptse = 0;
    }

    if (vlan_enabled(s) && is_vlan_txd(txd_lower) &&
        (tp->cptse || txd_lower & E1000_TXD_CMD_EOP)) {
        tp->vlan_needed = 1;
        stw_be_p(tp->vlan_header,
                      le16_to_cpup((uint16_t *)(s->mac_reg + VET)));
        stw_be_p(tp->vlan_header + 2,
                      le16_to_cpu(dp->upper.fields.special));
    }
        
    addr = le64_to_cpu(dp->buffer_addr);
    if (tp->tse && tp->cptse) {
        msh = tp->hdr_len + tp->mss;
        do {
            bytes = split_size;
            if (tp->size + bytes > msh)
                bytes = msh - tp->size;

            bytes = MIN(sizeof(tp->data) - tp->size, bytes);
            pci_dma_read(d, addr, tp->data + tp->size, bytes);
            sz = tp->size + bytes;
            if (sz >= tp->hdr_len && tp->size < tp->hdr_len) {
                memmove(tp->header, tp->data, tp->hdr_len);
            }
            tp->size = sz;
            addr += bytes;
            if (sz == msh) {
                xmit_seg(s);
                memmove(tp->data, tp->header, tp->hdr_len);
                tp->size = tp->hdr_len;
            }
        } while (split_size -= bytes);
    } else if (!tp->tse && tp->cptse) {
        // context descriptor TSE is not set, while data descriptor TSE is set
        DBGOUT(TXERR, "TCP segmentation error\n");
    } else {
        split_size = MIN(sizeof(tp->data) - tp->size, split_size);
        pci_dma_read(d, addr, tp->data + tp->size, split_size);
        tp->size += split_size;
    }

    if (!(txd_lower & E1000_TXD_CMD_EOP))
        return;
    if (!(tp->tse && tp->cptse && tp->size < tp->hdr_len)) {
        xmit_seg(s);
    }
    tp->tso_frames = 0;
    tp->sum_needed = 0;
    tp->vlan_needed = 0;
    tp->size = 0;
    tp->cptse = 0;
}

static uint32_t
txdesc_writeback(E1000State *s, dma_addr_t base, struct e1000_tx_desc *dp)
{
    PCIDevice *d = PCI_DEVICE(s);
    uint32_t txd_upper, txd_lower = le32_to_cpu(dp->lower.data);

    if (!(txd_lower & (E1000_TXD_CMD_RS|E1000_TXD_CMD_RPS)))
        return 0;
    txd_upper = (le32_to_cpu(dp->upper.data) | E1000_TXD_STAT_DD) &
                ~(E1000_TXD_STAT_EC | E1000_TXD_STAT_LC | E1000_TXD_STAT_TU);
    dp->upper.data = cpu_to_le32(txd_upper);
    pci_dma_write(d, base + ((char *)&dp->upper - (char *)dp),
                  &dp->upper, sizeof(dp->upper));
    return E1000_ICR_TXDW;
}

static uint64_t tx_desc_base(E1000State *s)
{
    uint64_t bah = s->mac_reg[TDBAH];
    uint64_t bal = s->mac_reg[TDBAL] & ~0xf;

    return (bah << 32) + bal;
}

static void
start_xmit(E1000State *s)
{
    PCIDevice *d = PCI_DEVICE(s);
    dma_addr_t base;
    struct e1000_tx_desc desc;
    uint32_t tdh_start = s->mac_reg[TDH], cause = E1000_ICS_TXQE;

    if (!(s->mac_reg[TCTL] & E1000_TCTL_EN)) {
        DBGOUT(TX, "tx disabled\n");
        return;
    }

    while (s->mac_reg[TDH] != s->mac_reg[TDT]) {
        base = tx_desc_base(s) +
               sizeof(struct e1000_tx_desc) * s->mac_reg[TDH];
        pci_dma_read(d, base, &desc, sizeof(desc));

        DBGOUT(TX, "index %d: %p : %x %x\n", s->mac_reg[TDH],
               (void *)(intptr_t)desc.buffer_addr, desc.lower.data,
               desc.upper.data);

        process_tx_desc(s, &desc);
        cause |= txdesc_writeback(s, base, &desc);

        if (++s->mac_reg[TDH] * sizeof(desc) >= s->mac_reg[TDLEN])
            s->mac_reg[TDH] = 0;
        /*
         * the following could happen only if guest sw assigns
         * bogus values to TDT/TDLEN.
         * there's nothing too intelligent we could do about this.
         */
        if (s->mac_reg[TDH] == tdh_start) {
            DBGOUT(TXERR, "TDH wraparound @%x, TDT %x, TDLEN %x\n",
                   tdh_start, s->mac_reg[TDT], s->mac_reg[TDLEN]);
            break;
        }
    }
    set_ics(s, 0, cause);
}

static int
receive_filter(E1000State *s, const uint8_t *buf, int size)
{
    static const uint8_t bcast[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const int mta_shift[] = {4, 3, 2, 0};
    uint32_t f, rctl = s->mac_reg[RCTL], ra[2], *rp;

    if (is_vlan_packet(s, buf) && vlan_rx_filter_enabled(s)) {
        uint16_t vid = be16_to_cpup((uint16_t *)(buf + 14));
        uint32_t vfta = le32_to_cpup((uint32_t *)(s->mac_reg + VFTA) +
                                     ((vid >> 5) & 0x7f));
        if ((vfta & (1 << (vid & 0x1f))) == 0)
            return 0;
    }

    if (rctl & E1000_RCTL_UPE)			// promiscuous
        return 1;

    if ((buf[0] & 1) && (rctl & E1000_RCTL_MPE))	// promiscuous mcast
        return 1;

    if ((rctl & E1000_RCTL_BAM) && !memcmp(buf, bcast, sizeof bcast))
        return 1;

    for (rp = s->mac_reg + RA; rp < s->mac_reg + RA + 32; rp += 2) {
        if (!(rp[1] & E1000_RAH_AV))
            continue;
        ra[0] = cpu_to_le32(rp[0]);
        ra[1] = cpu_to_le32(rp[1]);
        if (!memcmp(buf, (uint8_t *)ra, 6)) {
            DBGOUT(RXFILTER,
                   "unicast match[%d]: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   (int)(rp - s->mac_reg - RA)/2,
                   buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
            return 1;
        }
    }
    DBGOUT(RXFILTER, "unicast mismatch: %02x:%02x:%02x:%02x:%02x:%02x\n",
           buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);

    f = mta_shift[(rctl >> E1000_RCTL_MO_SHIFT) & 3];
    f = (((buf[5] << 8) | buf[4]) >> f) & 0xfff;
    if (s->mac_reg[MTA + (f >> 5)] & (1 << (f & 0x1f)))
        return 1;
    DBGOUT(RXFILTER,
           "dropping, inexact filter mismatch: %02x:%02x:%02x:%02x:%02x:%02x MO %d MTA[%d] %x\n",
           buf[0], buf[1], buf[2], buf[3], buf[4], buf[5],
           (rctl >> E1000_RCTL_MO_SHIFT) & 3, f >> 5,
           s->mac_reg[MTA + (f >> 5)]);

    return 0;
}

static void
e1000_set_link_status(NetClientState *nc)
{
    E1000State *s = qemu_get_nic_opaque(nc);
    uint32_t old_status = s->mac_reg[STATUS];

    if (nc->link_down) {
        e1000_link_down(s);
    } else {
        if (have_autoneg(s) &&
            !(s->phy_reg[PHY_STATUS] & MII_SR_AUTONEG_COMPLETE)) {
            /* emulate auto-negotiation if supported */
            timer_mod(s->autoneg_timer,
                      qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 500);
        } else {
            e1000_link_up(s);
        }
    }

    if (s->mac_reg[STATUS] != old_status)
        set_ics(s, 0, E1000_ICR_LSC);
}

static bool e1000_has_rxbufs(E1000State *s, size_t total_size)
{
    int bufs;
    /* Fast-path short packets */
    if (total_size <= s->rxbuf_size) {
        return s->mac_reg[RDH] != s->mac_reg[RDT];
    }
    if (s->mac_reg[RDH] < s->mac_reg[RDT]) {
        bufs = s->mac_reg[RDT] - s->mac_reg[RDH];
    } else if (s->mac_reg[RDH] > s->mac_reg[RDT]) {
        bufs = s->mac_reg[RDLEN] /  sizeof(struct e1000_rx_desc) +
            s->mac_reg[RDT] - s->mac_reg[RDH];
    } else {
        return false;
    }
    return total_size <= bufs * s->rxbuf_size;
}

static int
e1000_can_receive(NetClientState *nc)
{
    E1000State *s = qemu_get_nic_opaque(nc);

    return (s->mac_reg[STATUS] & E1000_STATUS_LU) &&
        (s->mac_reg[RCTL] & E1000_RCTL_EN) && e1000_has_rxbufs(s, 1);
}

static uint64_t rx_desc_base(E1000State *s)
{
    uint64_t bah = s->mac_reg[RDBAH];
    uint64_t bal = s->mac_reg[RDBAL] & ~0xf;

    return (bah << 32) + bal;
}

static ssize_t
e1000_receive_iov(NetClientState *nc, const struct iovec *iov, int iovcnt)
{
    E1000State *s = qemu_get_nic_opaque(nc);
    PCIDevice *d = PCI_DEVICE(s);
    struct e1000_rx_desc desc;
    dma_addr_t base;
    unsigned int n, rdt;
    uint32_t rdh_start;
    uint16_t vlan_special = 0;
    uint8_t vlan_status = 0;
    uint8_t min_buf[MIN_BUF_SIZE];
    struct iovec min_iov;
    uint8_t *filter_buf = iov->iov_base;
    size_t size = iov_size(iov, iovcnt);
    size_t iov_ofs = 0;
    size_t desc_offset;
    size_t desc_size;
    size_t total_size;

    if (!(s->mac_reg[STATUS] & E1000_STATUS_LU)) {
        return -1;
    }

    if (!(s->mac_reg[RCTL] & E1000_RCTL_EN)) {
        return -1;
    }

    /* Pad to minimum Ethernet frame length */
    if (size < sizeof(min_buf)) {
        iov_to_buf(iov, iovcnt, 0, min_buf, size);
        memset(&min_buf[size], 0, sizeof(min_buf) - size);
        min_iov.iov_base = filter_buf = min_buf;
        min_iov.iov_len = size = sizeof(min_buf);
        iovcnt = 1;
        iov = &min_iov;
    } else if (iov->iov_len < MAXIMUM_ETHERNET_HDR_LEN) {
        /* This is very unlikely, but may happen. */
        iov_to_buf(iov, iovcnt, 0, min_buf, MAXIMUM_ETHERNET_HDR_LEN);
        filter_buf = min_buf;
    }

    /* Discard oversized packets if !LPE and !SBP. */
    if ((size > MAXIMUM_ETHERNET_LPE_SIZE ||
        (size > MAXIMUM_ETHERNET_VLAN_SIZE
        && !(s->mac_reg[RCTL] & E1000_RCTL_LPE)))
        && !(s->mac_reg[RCTL] & E1000_RCTL_SBP)) {
        return size;
    }

    if (!receive_filter(s, filter_buf, size)) {
        return size;
    }

    if (vlan_enabled(s) && is_vlan_packet(s, filter_buf)) {
        vlan_special = cpu_to_le16(be16_to_cpup((uint16_t *)(filter_buf
                                                                + 14)));
        iov_ofs = 4;
        if (filter_buf == iov->iov_base) {
            memmove(filter_buf + 4, filter_buf, 12);
        } else {
            iov_from_buf(iov, iovcnt, 4, filter_buf, 12);
            while (iov->iov_len <= iov_ofs) {
                iov_ofs -= iov->iov_len;
                iov++;
            }
        }
        vlan_status = E1000_RXD_STAT_VP;
        size -= 4;
    }

    rdh_start = s->mac_reg[RDH];
    desc_offset = 0;
    total_size = size + fcs_len(s);
    if (!e1000_has_rxbufs(s, total_size)) {
            set_ics(s, 0, E1000_ICS_RXO);
            return -1;
    }
    do {
        desc_size = total_size - desc_offset;
        if (desc_size > s->rxbuf_size) {
            desc_size = s->rxbuf_size;
        }
        base = rx_desc_base(s) + sizeof(desc) * s->mac_reg[RDH];
        pci_dma_read(d, base, &desc, sizeof(desc));
        desc.special = vlan_special;
        desc.status |= (vlan_status | E1000_RXD_STAT_DD);
        if (desc.buffer_addr) {
            if (desc_offset < size) {
                size_t iov_copy;
                hwaddr ba = le64_to_cpu(desc.buffer_addr);
                size_t copy_size = size - desc_offset;
                if (copy_size > s->rxbuf_size) {
                    copy_size = s->rxbuf_size;
                }
                do {
                    iov_copy = MIN(copy_size, iov->iov_len - iov_ofs);
                    pci_dma_write(d, ba, iov->iov_base + iov_ofs, iov_copy);
                    copy_size -= iov_copy;
                    ba += iov_copy;
                    iov_ofs += iov_copy;
                    if (iov_ofs == iov->iov_len) {
                        iov++;
                        iov_ofs = 0;
                    }
                } while (copy_size);
            }
            desc_offset += desc_size;
            desc.length = cpu_to_le16(desc_size);
            if (desc_offset >= total_size) {
                desc.status |= E1000_RXD_STAT_EOP | E1000_RXD_STAT_IXSM;
            } else {
                /* Guest zeroing out status is not a hardware requirement.
                   Clear EOP in case guest didn't do it. */
                desc.status &= ~E1000_RXD_STAT_EOP;
            }
        } else { // as per intel docs; skip descriptors with null buf addr
            DBGOUT(RX, "Null RX descriptor!!\n");
        }
        pci_dma_write(d, base, &desc, sizeof(desc));

        if (++s->mac_reg[RDH] * sizeof(desc) >= s->mac_reg[RDLEN])
            s->mac_reg[RDH] = 0;
        /* see comment in start_xmit; same here */
        if (s->mac_reg[RDH] == rdh_start) {
            DBGOUT(RXERR, "RDH wraparound @%x, RDT %x, RDLEN %x\n",
                   rdh_start, s->mac_reg[RDT], s->mac_reg[RDLEN]);
            set_ics(s, 0, E1000_ICS_RXO);
            return -1;
        }
    } while (desc_offset < total_size);

    s->mac_reg[GPRC]++;
    s->mac_reg[TPR]++;
    /* TOR - Total Octets Received:
     * This register includes bytes received in a packet from the <Destination
     * Address> field through the <CRC> field, inclusively.
     */
    n = s->mac_reg[TORL] + size + /* Always include FCS length. */ 4;
    if (n < s->mac_reg[TORL])
        s->mac_reg[TORH]++;
    s->mac_reg[TORL] = n;

    n = E1000_ICS_RXT0;
    if ((rdt = s->mac_reg[RDT]) < s->mac_reg[RDH])
        rdt += s->mac_reg[RDLEN] / sizeof(desc);
    if (((rdt - s->mac_reg[RDH]) * sizeof(desc)) <= s->mac_reg[RDLEN] >>
        s->rxbuf_min_shift)
        n |= E1000_ICS_RXDMT0;

    set_ics(s, 0, n);

    return size;
}

static ssize_t
e1000_receive(NetClientState *nc, const uint8_t *buf, size_t size)
{
    const struct iovec iov = {
        .iov_base = (uint8_t *)buf,
        .iov_len = size
    };

    return e1000_receive_iov(nc, &iov, 1);
}

static uint32_t
mac_readreg(E1000State *s, int index)
{
    return s->mac_reg[index];
}

static uint32_t
mac_icr_read(E1000State *s, int index)
{
    uint32_t ret = s->mac_reg[ICR];

    DBGOUT(INTERRUPT, "ICR read: %x\n", ret);
    set_interrupt_cause(s, 0, 0);
    return ret;
}

static uint32_t
mac_read_clr4(E1000State *s, int index)
{
    uint32_t ret = s->mac_reg[index];

    s->mac_reg[index] = 0;
    return ret;
}

static uint32_t
mac_read_clr8(E1000State *s, int index)
{
    uint32_t ret = s->mac_reg[index];

    s->mac_reg[index] = 0;
    s->mac_reg[index-1] = 0;
    return ret;
}

static void
mac_writereg(E1000State *s, int index, uint32_t val)
{
    uint32_t macaddr[2];

    s->mac_reg[index] = val;

    if (index == RA + 1) {
        macaddr[0] = cpu_to_le32(s->mac_reg[RA]);
        macaddr[1] = cpu_to_le32(s->mac_reg[RA + 1]);
        qemu_format_nic_info_str(qemu_get_queue(s->nic), (uint8_t *)macaddr);
    }
}

static void
set_rdt(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val & 0xffff;
    if (e1000_has_rxbufs(s, 1)) {
        qemu_flush_queued_packets(qemu_get_queue(s->nic));
    }
}

static void
set_16bit(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val & 0xffff;
}

static void
set_dlen(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val & 0xfff80;
}

static void
set_tctl(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[index] = val;
    s->mac_reg[TDT] &= 0xffff;
    start_xmit(s);
}

static void
set_icr(E1000State *s, int index, uint32_t val)
{
    DBGOUT(INTERRUPT, "set_icr %x\n", val);
    set_interrupt_cause(s, 0, s->mac_reg[ICR] & ~val);
}

static void
set_imc(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[IMS] &= ~val;
    set_ics(s, 0, 0);
}

static void
set_ims(E1000State *s, int index, uint32_t val)
{
    s->mac_reg[IMS] |= val;
    set_ics(s, 0, 0);
}

#define getreg(x)	[x] = mac_readreg
static uint32_t (*macreg_readops[])(E1000State *, int) = {
    getreg(PBA),	getreg(RCTL),	getreg(TDH),	getreg(TXDCTL),
    getreg(WUFC),	getreg(TDT),	getreg(CTRL),	getreg(LEDCTL),
    getreg(MANC),	getreg(MDIC),	getreg(SWSM),	getreg(STATUS),
    getreg(TORL),	getreg(TOTL),	getreg(IMS),	getreg(TCTL),
    getreg(RDH),	getreg(RDT),	getreg(VET),	getreg(ICS),
    getreg(TDBAL),	getreg(TDBAH),	getreg(RDBAH),	getreg(RDBAL),
    getreg(TDLEN),      getreg(RDLEN),  getreg(RDTR),   getreg(RADV),
    getreg(TADV),       getreg(ITR),

    [TOTH] = mac_read_clr8,	[TORH] = mac_read_clr8,	[GPRC] = mac_read_clr4,
    [GPTC] = mac_read_clr4,	[TPR] = mac_read_clr4,	[TPT] = mac_read_clr4,
    [ICR] = mac_icr_read,	[EECD] = get_eecd,	[EERD] = flash_eerd_read,
    [CRCERRS ... MPC] = &mac_readreg,
    [RA ... RA+31] = &mac_readreg,
    [MTA ... MTA+127] = &mac_readreg,
    [VFTA ... VFTA+127] = &mac_readreg,
};
enum { NREADOPS = ARRAY_SIZE(macreg_readops) };

#define putreg(x)	[x] = mac_writereg
static void (*macreg_writeops[])(E1000State *, int, uint32_t) = {
    putreg(PBA),	putreg(EERD),	putreg(SWSM),	putreg(WUFC),
    putreg(TDBAL),	putreg(TDBAH),	putreg(TXDCTL),	putreg(RDBAH),
    putreg(RDBAL),	putreg(LEDCTL), putreg(VET),
    [TDLEN] = set_dlen,	[RDLEN] = set_dlen,	[TCTL] = set_tctl,
    [TDT] = set_tctl,	[MDIC] = set_mdic,	[ICS] = set_ics,
    [TDH] = set_16bit,	[RDH] = set_16bit,	[RDT] = set_rdt,
    [IMC] = set_imc,	[IMS] = set_ims,	[ICR] = set_icr,
    [EECD] = set_eecd,	[RCTL] = set_rx_control, [CTRL] = set_ctrl,
    [RDTR] = set_16bit, [RADV] = set_16bit,     [TADV] = set_16bit,
    [ITR] = set_16bit,
    [RA ... RA+31] = &mac_writereg,
    [MTA ... MTA+127] = &mac_writereg,
    [VFTA ... VFTA+127] = &mac_writereg,
};

enum { NWRITEOPS = ARRAY_SIZE(macreg_writeops) };

static void bcm5709_write_config(PCIDevice *pci_dev, uint32_t addr, uint32_t val_in, int l);

static uint32_t bcm5709_read_config(PCIDevice *pci_dev,
                                    uint32_t address, int len);

static void
e1000_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                 unsigned size)
{
    E1000State *s = opaque;
    PCIDevice *pd = PCI_DEVICE(s);
    unsigned int index = (addr & 0x1ffff) >> 2;

    if (index < NWRITEOPS && macreg_writeops[index]) {
        DBGOUT(MMIO, "MMIO write addr=0x%08x,val=0x%08"PRIx64"\n",
               (unsigned int)addr, val);
        macreg_writeops[index](s, index, val);
    } else if (index < NREADOPS && macreg_readops[index]) {
        DBGOUT(MMIO, "e1000_mmio_writel RO %x: 0x%04"PRIx64"\n", index<<2, val);
    } else if (addr > 0x80) {
        bcm5709_write_config(pd, 0x78, addr, size);
        bcm5709_write_config(pd, 0x80, val, size);
    } else if (addr == 0x68) {
        bcm5709_write_config(pd, addr, val, size);
    } else {
        DBGOUT(UNKNOWN, "MMIO unknown write addr=0x%08x,val=0x%08"PRIx64"\n",
               index<<2, val);
    }
}

static uint64_t
e1000_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    E1000State *s = opaque;
    PCIDevice *pd = PCI_DEVICE(s);
    unsigned int index = (addr & 0x1ffff) >> 2;

    if (index < NREADOPS && macreg_readops[index])
    {
        DBGOUT(MMIO, "MMIO read addr=0x%08x\n",
              (unsigned int)addr);
        return macreg_readops[index](s, index);
    }

    if (addr > 0x80) {
        bcm5709_write_config(pd, 0x78, addr, size);
        return bcm5709_read_config(pd, 0x80, size);
    } else {
        DBGOUT(UNKNOWN, "MMIO unknown read addr=0x%08x\n", index<<2);
        return 0;
    }
}

static const MemoryRegionOps e1000_mmio_ops = {
    .read = e1000_mmio_read,
    .write = e1000_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static bool is_version_1(void *opaque, int version_id)
{
    return version_id == 1;
}

static void e1000_pre_save(void *opaque)
{
    E1000State *s = opaque;
    NetClientState *nc = qemu_get_queue(s->nic);

    /* If the mitigation timer is active, emulate a timeout now. */
    if (s->mit_timer_on) {
        e1000_mit_timer(s);
    }

    /*
     * If link is down and auto-negotiation is supported and ongoing,
     * complete auto-negotiation immediately. This allows us to look
     * at MII_SR_AUTONEG_COMPLETE to infer link status on load.
     */
    if (nc->link_down && have_autoneg(s)) {
        s->phy_reg[PHY_STATUS] |= MII_SR_AUTONEG_COMPLETE;
    }
}

static int e1000_post_load(void *opaque, int version_id)
{
    E1000State *s = opaque;
    NetClientState *nc = qemu_get_queue(s->nic);

    if (!(s->compat_flags & E1000_FLAG_MIT)) {
        s->mac_reg[ITR] = s->mac_reg[RDTR] = s->mac_reg[RADV] =
            s->mac_reg[TADV] = 0;
        s->mit_irq_level = false;
    }
    s->mit_ide = 0;
    s->mit_timer_on = false;

    /* nc.link_down can't be migrated, so infer link_down according
     * to link status bit in mac_reg[STATUS].
     * Alternatively, restart link negotiation if it was in progress. */
    nc->link_down = (s->mac_reg[STATUS] & E1000_STATUS_LU) == 0;

    if (have_autoneg(s) &&
        !(s->phy_reg[PHY_STATUS] & MII_SR_AUTONEG_COMPLETE)) {
        nc->link_down = false;
        timer_mod(s->autoneg_timer,
                  qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 500);
    }

    return 0;
}

static bool e1000_mit_state_needed(void *opaque)
{
    E1000State *s = opaque;

    return s->compat_flags & E1000_FLAG_MIT;
}

static const VMStateDescription vmstate_e1000_mit_state = {
    .name = "bcm5709/mit_state",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(mac_reg[RDTR], E1000State),
        VMSTATE_UINT32(mac_reg[RADV], E1000State),
        VMSTATE_UINT32(mac_reg[TADV], E1000State),
        VMSTATE_UINT32(mac_reg[ITR], E1000State),
        VMSTATE_BOOL(mit_irq_level, E1000State),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_e1000 = {
    .name = "bcm5709",
    .version_id = 2,
    .minimum_version_id = 1,
    .pre_save = e1000_pre_save,
    .post_load = e1000_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(parent_obj, E1000State),
        VMSTATE_UNUSED_TEST(is_version_1, 4), /* was instance id */
        VMSTATE_UNUSED(4), /* Was mmio_base.  */
        VMSTATE_UINT32(rxbuf_size, E1000State),
        VMSTATE_UINT32(rxbuf_min_shift, E1000State),
        VMSTATE_UINT32(eecd_state.val_in, E1000State),
        VMSTATE_UINT16(eecd_state.bitnum_in, E1000State),
        VMSTATE_UINT16(eecd_state.bitnum_out, E1000State),
        VMSTATE_UINT16(eecd_state.reading, E1000State),
        VMSTATE_UINT32(eecd_state.old_eecd, E1000State),
        VMSTATE_UINT8(tx.ipcss, E1000State),
        VMSTATE_UINT8(tx.ipcso, E1000State),
        VMSTATE_UINT16(tx.ipcse, E1000State),
        VMSTATE_UINT8(tx.tucss, E1000State),
        VMSTATE_UINT8(tx.tucso, E1000State),
        VMSTATE_UINT16(tx.tucse, E1000State),
        VMSTATE_UINT32(tx.paylen, E1000State),
        VMSTATE_UINT8(tx.hdr_len, E1000State),
        VMSTATE_UINT16(tx.mss, E1000State),
        VMSTATE_UINT16(tx.size, E1000State),
        VMSTATE_UINT16(tx.tso_frames, E1000State),
        VMSTATE_UINT8(tx.sum_needed, E1000State),
        VMSTATE_INT8(tx.ip, E1000State),
        VMSTATE_INT8(tx.tcp, E1000State),
        VMSTATE_BUFFER(tx.header, E1000State),
        VMSTATE_BUFFER(tx.data, E1000State),
        VMSTATE_UINT16_ARRAY(eeprom_data, E1000State, 64),
        VMSTATE_UINT16_ARRAY(phy_reg, E1000State, 0x20),
        VMSTATE_UINT32(mac_reg[CTRL], E1000State),
        VMSTATE_UINT32(mac_reg[EECD], E1000State),
        VMSTATE_UINT32(mac_reg[EERD], E1000State),
        VMSTATE_UINT32(mac_reg[GPRC], E1000State),
        VMSTATE_UINT32(mac_reg[GPTC], E1000State),
        VMSTATE_UINT32(mac_reg[ICR], E1000State),
        VMSTATE_UINT32(mac_reg[ICS], E1000State),
        VMSTATE_UINT32(mac_reg[IMC], E1000State),
        VMSTATE_UINT32(mac_reg[IMS], E1000State),
        VMSTATE_UINT32(mac_reg[LEDCTL], E1000State),
        VMSTATE_UINT32(mac_reg[MANC], E1000State),
        VMSTATE_UINT32(mac_reg[MDIC], E1000State),
        VMSTATE_UINT32(mac_reg[MPC], E1000State),
        VMSTATE_UINT32(mac_reg[PBA], E1000State),
        VMSTATE_UINT32(mac_reg[RCTL], E1000State),
        VMSTATE_UINT32(mac_reg[RDBAH], E1000State),
        VMSTATE_UINT32(mac_reg[RDBAL], E1000State),
        VMSTATE_UINT32(mac_reg[RDH], E1000State),
        VMSTATE_UINT32(mac_reg[RDLEN], E1000State),
        VMSTATE_UINT32(mac_reg[RDT], E1000State),
        VMSTATE_UINT32(mac_reg[STATUS], E1000State),
        VMSTATE_UINT32(mac_reg[SWSM], E1000State),
        VMSTATE_UINT32(mac_reg[TCTL], E1000State),
        VMSTATE_UINT32(mac_reg[TDBAH], E1000State),
        VMSTATE_UINT32(mac_reg[TDBAL], E1000State),
        VMSTATE_UINT32(mac_reg[TDH], E1000State),
        VMSTATE_UINT32(mac_reg[TDLEN], E1000State),
        VMSTATE_UINT32(mac_reg[TDT], E1000State),
        VMSTATE_UINT32(mac_reg[TORH], E1000State),
        VMSTATE_UINT32(mac_reg[TORL], E1000State),
        VMSTATE_UINT32(mac_reg[TOTH], E1000State),
        VMSTATE_UINT32(mac_reg[TOTL], E1000State),
        VMSTATE_UINT32(mac_reg[TPR], E1000State),
        VMSTATE_UINT32(mac_reg[TPT], E1000State),
        VMSTATE_UINT32(mac_reg[TXDCTL], E1000State),
        VMSTATE_UINT32(mac_reg[WUFC], E1000State),
        VMSTATE_UINT32(mac_reg[VET], E1000State),
        VMSTATE_UINT32_SUB_ARRAY(mac_reg, E1000State, RA, 32),
        VMSTATE_UINT32_SUB_ARRAY(mac_reg, E1000State, MTA, 128),
        VMSTATE_UINT32_SUB_ARRAY(mac_reg, E1000State, VFTA, 128),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (VMStateSubsection[]) {
        {
            .vmsd = &vmstate_e1000_mit_state,
            .needed = e1000_mit_state_needed,
        }, {
            /* empty */
        }
    }
};

/* PCI interface */

static void
e1000_mmio_setup(E1000State *d)
{
//    int i;
//    const uint32_t excluded_regs[] = {
//        E1000_MDIC, E1000_ICR, E1000_ICS, E1000_IMS,
//        E1000_IMC, E1000_TCTL, E1000_TDT, PNPMMIO_SIZE
//    };

    memory_region_init_io(&d->mmio, OBJECT(d), &e1000_mmio_ops, d,
                          "bcm5709-mmio", PNPMMIO_SIZE);
//    memory_region_add_coalescing(&d->mmio, 0, excluded_regs[0]);
//    for (i = 0; excluded_regs[i] != PNPMMIO_SIZE; i++)
//        memory_region_add_coalescing(&d->mmio, excluded_regs[i] + 4,
//                                     excluded_regs[i+1] - excluded_regs[i] - 4);
//    memory_region_init_io(&d->io, OBJECT(d), &e1000_io_ops, d, "e1000-io", IOPORT_SIZE);
}

static void
e1000_cleanup(NetClientState *nc)
{
    E1000State *s = qemu_get_nic_opaque(nc);

    s->nic = NULL;
}

static void
pci_e1000_uninit(PCIDevice *dev)
{
    E1000State *d = E1000(dev);

    timer_del(d->autoneg_timer);
    timer_free(d->autoneg_timer);
    timer_del(d->mit_timer);
    timer_free(d->mit_timer);
    qemu_del_nic(d->nic);
}

static NetClientInfo net_e1000_info = {
    .type = NET_CLIENT_OPTIONS_KIND_NIC,
    .size = sizeof(NICState),
    .can_receive = e1000_can_receive,
    .receive = e1000_receive,
    .receive_iov = e1000_receive_iov,
    .cleanup = e1000_cleanup,
    .link_status_changed = e1000_set_link_status,
};

static int pci_e1000_init(PCIDevice *pci_dev)
{
    DeviceState *dev = DEVICE(pci_dev);
    E1000State *d = E1000(pci_dev);
//    PCIDeviceClass *pdc = PCI_DEVICE_GET_CLASS(pci_dev);
    uint8_t *pci_conf;
//    uint16_t checksum = 0;
//    int i;
    uint8_t *macaddr;

    pci_conf = pci_dev->config;

    memset(pci_conf+0x33, 0, 256-0x32);

    /* TODO: RST# value should be 0, PCI spec 6.2.4 */
    pci_conf[PCI_CACHE_LINE_SIZE] = 0x10;

    pci_conf[PCI_INTERRUPT_PIN] = 1; /* interrupt pin A */

    e1000_mmio_setup(d);

    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_MEM_PREFETCH, &d->mmio);
//    pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &d->mmio);

//    pci_register_bar(pci_dev, 1, PCI_BASE_ADDRESS_SPACE_IO, &d->io);

//    memmove(d->eeprom_data, e1000_eeprom_template,
//        sizeof e1000_eeprom_template);
    qemu_macaddr_default_if_unset(&d->conf.macaddr);
    macaddr = d->conf.macaddr.a;

    memset(d->bnx2_nvram, 0, sizeof(d->bnx2_nvram));

    d->fp[0] = fopen("/tmp/bcm5709/rv2p_proc1", "w+");
    d->fp[1] = fopen("/tmp/bcm5709/rv2p_proc2", "w+");
    d->fp[2] = fopen("/tmp/bcm5709/txp", "w+");
    d->fp[3] = fopen("/tmp/bcm5709/rxp", "w+");
    d->fp[4] = fopen("/tmp/bcm5709/tpat", "w+");
    d->fp[5] = fopen("/tmp/bcm5709/com", "w+");
    d->fp[6] = fopen("/tmp/bcm5709/mcp", "w+");
    d->fp[7] = fopen("/tmp/bcm5709/cp", "w+");

    d->rv2p_hi = 0;
    d->rv2p_lo = 0;

    d->bnx2_nvram[0x50] = 0x11;
    d->bnx2_nvram[0x51] = 0x22;
    d->bnx2_nvram[0x52] = 0x33;
    d->bnx2_nvram[0x53] = 0x44;
    d->bnx2_nvram[0x54] = 0x55;
    d->bnx2_nvram[0x55] = 0x66;
    d->bnx2_nvram[0x56] = 0x77;
    d->bnx2_nvram[0x57] = 0x88;
    d->bnx2_nvram[0x58] = 0x99;
    d->bnx2_nvram[0x59] = 0xaa;

    d->bnx2_nvram[0x23] = 0x44;
    d->bnx2_nvram[0x22] = 0x56;
    d->bnx2_nvram[0x21] = 0x49;
    d->bnx2_nvram[0x20] = 0x00;

#if 0
    for (i = 0; i < 3; i++)
        d->eeprom_data[i] = (macaddr[2*i+1]<<8) | macaddr[2*i];
    d->eeprom_data[11] = d->eeprom_data[13] = pdc->device_id;
    for (i = 0; i < EEPROM_CHECKSUM_REG; i++)
        checksum += d->eeprom_data[i];
    checksum = (uint16_t) EEPROM_SUM - checksum;
    d->eeprom_data[EEPROM_CHECKSUM_REG] = checksum;
#endif
    d->nic = qemu_new_nic(&net_e1000_info, &d->conf,
                          object_get_typename(OBJECT(d)), dev->id, d);

    qemu_format_nic_info_str(qemu_get_queue(d->nic), macaddr);

    add_boot_device_path(d->conf.bootindex, dev, "/ethernet-phy@0");

    d->autoneg_timer = timer_new_ms(QEMU_CLOCK_VIRTUAL, e1000_autoneg_timer, d);
    d->mit_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, e1000_mit_timer, d);

    return 0;
}

static void qdev_e1000_reset(DeviceState *dev)
{
    E1000State *d = E1000(dev);
    e1000_reset(d);
}

#define R_CS 1
#define CPU_NB_REGS 8

#define target_ulong uint32_t

typedef struct SegmentCache {
    uint32_t selector;
    target_ulong base;
    uint32_t limit;
    uint32_t flags;
} SegmentCache;

typedef struct CPUX86State {
    /* standard registers */
    target_ulong regs[CPU_NB_REGS];
    target_ulong eip;
    target_ulong eflags; /* eflags register. During CPU emulation, CC
                        flags and DF are set to zero because they are
                        stored elsewhere */

    /* emulator internal eflags handling */
    target_ulong cc_dst;
    target_ulong cc_src;
    target_ulong cc_src2;
    uint32_t cc_op;
    int32_t df; /* D flag : 1 if D = 0, -1 if D = 1 */
    uint32_t hflags; /* TB flags, see HF_xxx constants. These flags
                        are known at translation time. */
    uint32_t hflags2; /* various other flags, see HF2_xxx constants. */

    /* segments */
    SegmentCache segs[6]; /* selector values */
} CPUX86State;

static uint32_t bcm5709_read_config(PCIDevice *pci_dev,
                                    uint32_t address, int len)
{
    uint32_t reg;
    uint32_t val = 0;
    static uint32_t alloc = 0x0;
#if 0
    uint32_t seg, eip;
    CPUState *cpu;
    CPUX86State *env;
#endif
    E1000State *d = E1000(pci_dev);

    memcpy(&val, pci_dev->config + address, len);
#if 0
    cpu = qemu_get_cpu(0);
    cpu_synchronize_state(cpu);
    env = (CPUX86State *)cpu->env_ptr;
    seg = env->segs[R_CS].base;
    eip = env->eip;
#endif
    if (address == 0x80) {
        reg = (pci_dev->config[0x7b] << 24) | (pci_dev->config[0x7a] << 16) | (pci_dev->config[0x79] << 8) | pci_dev->config[0x78];
        switch (reg) {
        case 0xb4: // BNX2_PCICFG_DEVICE_CONTROL
            val = 0x0;
            DBGOUT(UNKNOWN,"...BNX2_PCICFG_DEVICE_CONTROL: %08x\n", val);
            break;
        case 0x408: // BNX2_PCI_CONFIG_2
            DBGOUT(UNKNOWN,"...BNX2_PCI_CONFIG_2 (%x): %08x\n", reg, val);
            break;
        case 0x418: // BNX2_PCI_SWAP_DIAG0
            val = 0x01020304;
            DBGOUT(UNKNOWN,"...BNX2_PCI_SWAP_DIAG0: %08x\n", val);
            break;
        case 0x800: // BNX2_MISC_COMMAND
            DBGOUT(UNKNOWN,"...BNX2_MISC_COMMAND (%x): %08x\n", reg, val);
            break;
        case 0x808: // BNX2_MISC_ID
            val = 0x57092000; // BNX2_CHIP_REV_Cx
            DBGOUT(UNKNOWN,"...BNX2_MISC_ID (%x): %08x\n", reg, val);
            break;
        case 0x814: // BNX2_MISC_ENABLE_CLR_BITS
//            val = 0x0;
            DBGOUT(UNKNOWN,"...BNX2_MISC_ENABLE_CLR_BITS (%x): %08x\n", reg, val);
            break;
        case 0x8c8: // BNX2_MISC_NEW_CORE_CTL
            val = 0x0;
            DBGOUT(UNKNOWN,"...BNX2_MISC_NEW_CORE_CTL: %08x\n", val);
            break;
        case 0x8e8: // BNX2_MISC_PPIO_EVENT
//            val = 0x0;
            DBGOUT(UNKNOWN,"...BNX2_MISC_PPIO_EVENT (%x): %08x\n", reg, val);
            break;
        case 0x8ec: // BNX2_MISC_DUAL_MEDIA_CTRL
//            val = 0x0;
            DBGOUT(UNKNOWN,"...BNX2_MISC_DUAL_MEDIA_CTRL (%x): %08x\n", reg, val);
            break;
        case 0x1400: // BNX2_EMAC_MODE
//            val = 0x0;
            DBGOUT(UNKNOWN,"...BNX2_EMAC_MODE (%x): %08x\n", reg, val);
            break;
        case 0x1404: // BNX2_EMAC_STATUS
//            val = 0x0;
            DBGOUT(UNKNOWN,"...BNX2_EMAC_STATUS (%x): %08x\n", reg, val);
            break;
        case 0x14ac: // BNX2_EMAC_MDIO_COMM
            val = 0x0;
            DBGOUT(UNKNOWN,"...BNX2_EMAC_MDIO_COMM (%x): %08x\n", reg, val);
            break;
        case 0x14c8: // BNX2_EMAC_RX_MODE
            DBGOUT(UNKNOWN,"...BNX2_EMAC_RX_MODE (%x): %08x\n", reg, val);
            break;
        case 0x2808: // BNX2_RV2P_CONFIG
            DBGOUT(UNKNOWN,"...BNX2_RV2P_CONFIG (%x): %08x\n", reg, val);
            break;
        case 0x3c08: // BNX2_MQ_CONFIG
            DBGOUT(UNKNOWN,"...BNX2_MQ_CONFIG (%x): %08x\n", reg, val);
            break;
        case 0x4448: // BUFMGR_TX_DMA_ALLOC_RESP
//            alloc += 0x100;
            val = alloc;
            DBGOUT(UNKNOWN,"...BUFMGR_TX_DMA_ALLOC_RESP (%x): %08x\n", reg, val);
            break;
        case 0x5008: // BNX2_TBDR_CONFIG
            DBGOUT(UNKNOWN,"...BNX2_TBDR_CONFIG (%x): %08x\n", reg, val);
            break;
        case 0x6400: // BNX2_NVM_COMMAND
            val = (1L<<3); // BNX2_NVM_COMMAND_DONE
            DBGOUT(UNKNOWN,"...BNX2_NVM_COMMAND (%x): %04x (DONE)\n", reg, val);
            break;
        case 0x6410: // BNX2_NVM_READ
            memcpy(&val, d->bnx2_nvram + d->bnx2_nvram_off, 4);
            DBGOUT(UNKNOWN,"...BNX2_NVM_READ (%x): %04x\n", d->bnx2_nvram_off, val);
            break;
        case 0x6414: // BNX2_NVM_CFG1
            val = 0x0;
            DBGOUT(UNKNOWN,"...BNX2_NVM_CFG1: %04x\n", val);
            break;
        case 0x6420: // BNX2_NVM_SW_ARB
            val = (1L<<10); // BNX2_NVM_SW_ARB_ARB_ARB2
//            val = (1L<<9); // BNX2_NVM_SW_ARB_ARB_ARB2
            DBGOUT(UNKNOWN,"...BNX2_NVM_SW_ARB (%x): %04x\n", reg, val);
            break;
        case 0x6800: // BNX2_HC_COMMAND
            DBGOUT(UNKNOWN,"...BNX2_HC_COMMAND (%x): %04x\n", reg, val);
            break;
        case 0x680c: // BNX2_HC_ATTN_BITS_ENABLE
            DBGOUT(UNKNOWN,"...BNX2_HC_ATTN_BITS_ENABLE (%x): %04x\n", reg, val);
            break;
        case 0x45000: // BNX2_TXP_CPU_MODE
            val = d->cpu_txp[0];
            DBGOUT(UNKNOWN,"...BNX2_TXP_CPU_MODE (%x): %04x\n", reg, val);
            break;
        case 0x85000: // BNX2_TPAT_CPU_MODE
            val = d->cpu_tpat[0];
            DBGOUT(UNKNOWN,"...BNX2_TPAT_CPU_MODE (%x): %04x\n", reg, val);
            break;
        case 0xc5000: // BNX2_RXP_CPU_MODE
            val = d->cpu_rxp[0];
            DBGOUT(UNKNOWN,"...BNX2_RXP_CPU_MODE (%x): %04x\n", reg, val);
            break;
        case 0x105000: // BNX2_COM_CPU_MODE
            val = d->cpu_com[0];
            DBGOUT(UNKNOWN,"...BNX2_COM_CPU_MODE (%x): %04x\n", reg, val);
            break;
        case 0x1400a0: // BNX2_MCP_TOE_ID
            val = (1L<<31); // BNX2_MCP_TOE_ID_FUNCTION_ID
            DBGOUT(UNKNOWN,"...BNX2_MCP_TOE_ID (%x): %04x\n", reg, val);
            break;
        case 0x160000: // BNX2_SHM_HDR_SIGNATURE
//            val = 0x53530000;
            DBGOUT(UNKNOWN,"...BNX2_SHM_HDR_SIGNATURE: %08x\n", val);
            break;
        case 0x160004: // BNX2_SHM_HDR_ADDR_0 + 4
        case 0x160008: // BNX2_SHM_HDR_ADDR_0 + 8
            val = 0x00167c00; // for the second head
            DBGOUT(UNKNOWN,"...BNX2_SHM_HDR_ADDR_0(%08x): %08x\n", reg, val);
            break;
        default:
            if ((reg &~ 0xff) == 0x167c00) { // HOST_VIEW_SHMEM_BASE
                memcpy(&val, d->bnx2_nvram + (reg & 0xff), 4);
                if ((reg & 0xff) != 0x20)
                    DBGOUT(UNKNOWN, "...SHMEM  read %04x@%02x\n", val, reg & 0xff);
                break;
            }
            val = 0;
            DBGOUT(UNKNOWN, "PCI  read addr=0x%08x val=0x%02x reg=%x\n", address, val, reg);
        }
    } else if (address == 0x68) { // BNX2_PCICFG_MISC_CONFIG
        DBGOUT(UNKNOWN, "...BNX2_PCICFG_MISC_CONFIG: %08x\n", val);
    } else if (address == 0x84) { // BNX2_PCICFG_INT_ACK_CMD
        DBGOUT(UNKNOWN, "...BNX2_PCICFG_INT_ACK_CMD: %08x\n", val);
    } else if (address == 0x94) { // BNX2_PCICFG_MAILBOX_QUEUE_DATA
        DBGOUT(UNKNOWN, "...BNX2_PCICFG_MAILBOX_QUEUE_DATA: %08x\n", val);
    } else {
        DBGOUT(UNKNOWN, "PCI  read addr=0x%08x val=0x%02x\n", address, val);
    }

    return le32_to_cpu(val);
}

static void bcm5709_write_config(PCIDevice *pci_dev, uint32_t addr, uint32_t val_in, int l)
{
    int i;
    uint32_t reg;
    uint32_t val = val_in;
    E1000State *d = E1000(pci_dev);

    for (i = 0; i < l; val >>= 8, ++i) {
        uint8_t wmask = pci_dev->wmask[addr + i];
        uint8_t w1cmask = pci_dev->w1cmask[addr + i];
        assert(!(wmask & w1cmask));
        pci_dev->config[addr + i] = (pci_dev->config[addr + i] & ~wmask) | (val & wmask);
        pci_dev->config[addr + i] &= ~(val & w1cmask); /* W1C: Write 1 to Clear */
    }

    if (addr == 0x80) {
        reg = (pci_dev->config[0x7b] << 24) | (pci_dev->config[0x7a] << 16) | (pci_dev->config[0x79] << 8) | pci_dev->config[0x78];
        switch (reg) {
        case 0x408: // BNX2_PCI_CONFIG_2
            DBGOUT(UNKNOWN, "BNX2_PCI_CONFIG_2: %08x\n", val_in);
            break;
        case 0x800: // BNX2_MISC_COMMAND
            DBGOUT(UNKNOWN, "BNX2_MISC_COMMAND: %08x\n", val_in);
            break;
        case 0x810: // BNX2_MISC_ENABLE_SET_BITS
            DBGOUT(UNKNOWN, "BNX2_MISC_ENABLE_SET_BITS: %08x\n", val_in);
            break;
        case 0x814: // BNX2_MISC_ENABLE_CLR_BITS
            DBGOUT(UNKNOWN, "BNX2_MISC_ENABLE_CLR_BITS: %08x\n", val_in);
            break;
        case 0x8c8: // BNX2_MISC_NEW_CORE_CTL
            DBGOUT(UNKNOWN, "BNX2_MISC_NEW_CORE_CTL: %08x\n", val_in);
            break;
        case 0xc08: // BNX2_DMA_CONFIG
            DBGOUT(UNKNOWN, "BNX2_DMA_CONFIG: %08x\n", val_in);
            break;
        case 0x1008: // BNX2_CTX_VIRT_ADDR
            DBGOUT(UNKNOWN, "BNX2_CTX_VIRT_ADDR: %08x\n", val_in);
            break;
        case 0x100c: // BNX2_CTX_PAGE_TBL
            DBGOUT(UNKNOWN, "BNX2_CTX_PAGE_TBL: %08x\n", val_in);
            break;
        case 0x1010: // BNX2_CTX_DATA_ADR
            DBGOUT(UNKNOWN, "BNX2_CTX_DATA_ADR: %08x\n", val_in);
            break;
        case 0x1014: // BNX2_CTX_DATA
            DBGOUT(UNKNOWN, "BNX2_CTX_DATA: %08x\n", val_in);
            break;
        case 0x1400: // BNX2_EMAC_MODE
            DBGOUT(UNKNOWN, "BNX2_EMAC_MODE: %08x\n", val_in);
            break;
        case 0x1404: // BNX2_EMAC_STATUS
            DBGOUT(UNKNOWN, "BNX2_EMAC_STATUS: %08x\n", val_in);
            break;
        case 0x1408: // BNX2_EMAC_ATTENTION_ENA
            DBGOUT(UNKNOWN, "BNX2_EMAC_ATTENTION_ENA: %08x\n", val_in);
            break;
        case 0x1410: // BNX2_EMAC_MAC_MATCH0
            DBGOUT(UNKNOWN, "BNX2_EMAC_MAC_MATCH0: %08x\n", val_in);
            break;
        case 0x1414: // BNX2_EMAC_MAC_MATCH1
            DBGOUT(UNKNOWN, "BNX2_EMAC_MAC_MATCH1: %08x\n", val_in);
            break;
        case 0x1498: // BNX2_EMAC_BACKOFF_SEED
            DBGOUT(UNKNOWN, "BNX2_EMAC_BACKOFF_SEED: %08x\n", val_in);
            break;
        case 0x149c: // BNX2_EMAC_RX_MTU_SIZE
            DBGOUT(UNKNOWN, "BNX2_EMAC_RX_MTU_SIZE: %d\n", val_in);
            break;
        case 0x14ac: // BNX2_EMAC_MDIO_COMM
            DBGOUT(UNKNOWN, "BNX2_EMAC_MDIO_COMM: %08x\n", val_in);
            break;
        case 0x14c4: // BNX2_EMAC_TX_LENGTHS
            DBGOUT(UNKNOWN, "BNX2_EMAC_TX_LENGTHS: %08x\n", val_in);
            break;
        case 0x14c8: // BNX2_EMAC_RX_MODE
            DBGOUT(UNKNOWN, "BNX2_EMAC_RX_MODE: %08x\n", val_in);
            break;
        case 0x14d0: // BNX2_EMAC_MULTICAST_HASH0
            DBGOUT(UNKNOWN, "BNX2_EMAC_MULTICAST_HASH0: %08x\n", val_in);
            break;
        case 0x14d4: // BNX2_EMAC_MULTICAST_HASH1
            DBGOUT(UNKNOWN, "BNX2_EMAC_MULTICAST_HASH1: %08x\n", val_in);
            break;
        case 0x14d8: // BNX2_EMAC_MULTICAST_HASH2
            DBGOUT(UNKNOWN, "BNX2_EMAC_MULTICAST_HASH2: %08x\n", val_in);
            break;
        case 0x14dc: // BNX2_EMAC_MULTICAST_HASH3
            DBGOUT(UNKNOWN, "BNX2_EMAC_MULTICAST_HASH3: %08x\n", val_in);
            break;
        case 0x14e0: // BNX2_EMAC_MULTICAST_HASH4
            DBGOUT(UNKNOWN, "BNX2_EMAC_MULTICAST_HASH4: %08x\n", val_in);
            break;
        case 0x14e4: // BNX2_EMAC_MULTICAST_HASH5
            DBGOUT(UNKNOWN, "BNX2_EMAC_MULTICAST_HASH5: %08x\n", val_in);
            break;
        case 0x14e8: // BNX2_EMAC_MULTICAST_HASH6
            DBGOUT(UNKNOWN, "BNX2_EMAC_MULTICAST_HASH6: %08x\n", val_in);
            break;
        case 0x14ec: // BNX2_EMAC_MULTICAST_HASH7
            DBGOUT(UNKNOWN, "BNX2_EMAC_MULTICAST_HASH7: %08x\n", val_in);
            break;
        case 0x1820: // BNX2_RPM_SORT_USER0
            DBGOUT(UNKNOWN, "BNX2_RPM_SORT_USER0: %08x\n", val_in);
            break;
        case 0x2800: // BNX2_RV2P_COMMAND
            if (val_in & (1L<<16)) {
                // BNX2_RV2P_COMMAND_PROC1_RESET
                DBGOUT(UNKNOWN, "-> RV2P_PROC1_RESET\n");
            }
            if (val_in & (1L<<17)) {
                // BNX2_RV2P_COMMAND_PROC2_RESET
                DBGOUT(UNKNOWN, "-> RV2P_PROC2_RESET\n");
            }
            break;
        case 0x2808: // BNX2_RV2P_CONFIG
            DBGOUT(UNKNOWN, "BNX2_RV2P_CONFIG: %08x\n", val_in);
            break;
        case 0x2830: // BNX2_RV2P_INSTR_HIGH
            DBGOUT(UNKNOWN, "RV2P_HI: %08x\n", val_in);
            d->rv2p_hi = val_in;
            break;
        case 0x2834: // BNX2_RV2P_INSTR_LOW
            DBGOUT(UNKNOWN, "RV2P_LO: %08x\n", val_in);
            d->rv2p_lo = val_in;
            break;
        case 0x2838: // BNX2_RV2P_PROC1_ADDR_CMD
            DBGOUT(UNKNOWN, "RV2P_PROC1: %08x\n", val_in &~ (1<<31));
            fwrite(&d->rv2p_hi, 4, 1, d->fp[0]);
            fwrite(&d->rv2p_lo, 4, 1, d->fp[0]);
            break;
        case 0x283c: // BNX2_RV2P_PROC2_ADDR_CMD
            DBGOUT(UNKNOWN, "RV2P_PROC2: %08x\n", val_in &~ (1<<31));
            fwrite(&d->rv2p_hi, 4, 1, d->fp[1]);
            fwrite(&d->rv2p_lo, 4, 1, d->fp[1]);
            break;
        case 0x3c08: // BNX2_MQ_CONFIG
            DBGOUT(UNKNOWN, "BNX2_MQ_CONFIG: %08x\n", val_in);
            break;
        case 0x3c1c: // BNX2_MQ_KNL_BYP_WIND_START
            DBGOUT(UNKNOWN, "BNX2_MQ_KNL_BYP_WIND_START: %08x\n", val_in);
            break;
        case 0x3c20: // BNX2_MQ_KNL_WIND_END
            DBGOUT(UNKNOWN, "BNX2_MQ_KNL_BYP_WIND_END: %08x\n", val_in);
            break;
        case 0x5008: // BNX2_TBDR_CONFIG
            DBGOUT(UNKNOWN, "BNX2_TBDR_CONFIG: %08x\n", val_in);
            break;
        case 0x6400: // BNX2_NVM_COMMAND
            if (val_in & (1L<<3)) {
                // BNX2_NVM_COMMAND_DONE
            }
            if (val_in & (1L<<4)) {
                // BNX2_NVM_COMMAND_DOIT
            }
            if (val_in & (1L<<7)) {
                // BNX2_NVM_COMMAND_FIRST
            }
            if (val_in & (1L<<8)) {
                // BNX2_NVM_COMMAND_LAST
            }
            DBGOUT(UNKNOWN, "BNX2_NVM_COMMAND: %08x\n", val_in);
            break;
        case 0x640c: // BNX2_NVM_ADDR
            d->bnx2_nvram_off = val_in;
            DBGOUT(UNKNOWN, "BNX2_NVM_ADDR: %08x\n", val_in);
            break;
        case 0x6420: // BNX2_NVM_SW_ARB
            if (val_in == (1L<<2)) {} // BNX2_NVM_SW_ARB_ARB_REQ_SET2
            if (val_in == (1L<<6)) {} // BNX2_NVM_SW_ARB_ARB_REQ_CLR2
            DBGOUT(UNKNOWN, "BNX2_NVM_SW_ARB: %08x\n", val_in);
            break;
        case 0x6424: // BNX2_NVM_ACCESS_ENABLE
            if (val_in == ((1L<<0) | (1L<<1))) {} // BNX2_NVM_ACCESS_ENABLE_EN | BNX2_NVM_ACCESS_ENABLE_WR_EN
            DBGOUT(UNKNOWN, "BNX2_NVM_ACCESS_ENABLE: %08x\n", val_in);
            break;
        case 0x6800: // BNX2_HC_COMMAND
            DBGOUT(UNKNOWN, "BNX2_HC_COMMAND: %08x\n", val_in);
            break;
        case 0x680c: // BNX2_HC_ATTN_BITS_ENABLE
            DBGOUT(UNKNOWN, "BNX2_HC_ATTN_BITS_ENABLE: %08x\n", val_in);
            break;
        case 0x6810: // BNX2_HC_STATUS_ADDR_L
            DBGOUT(UNKNOWN, "BNX2_HC_STATUS_ADDR_L: %08x\n", val_in);
            break;
        case 0x6814: // BNX2_HC_STATUS_ADDR_H
            DBGOUT(UNKNOWN, "BNX2_HC_STATUS_ADDR_H: %08x\n", val_in);
            break;
        case 0x6820: // BNX2_HC_TX_QUICK_CONS_TRIP
            DBGOUT(UNKNOWN, "BNX2_HC_TX_QUICK_CONS_TRIP: %08x\n", val_in);
            break;
        case 0x6824: // BNX2_HC_COMP_PROD_TRIP
            DBGOUT(UNKNOWN, "BNX2_HC_COMP_PROD_TRIP: %08x\n", val_in);
            break;
        case 0x6828: // BNX2_HC_RX_QUICK_CONS_TRIP
            DBGOUT(UNKNOWN, "BNX2_HC_RX_QUICK_CONS_TRIP: %08x\n", val_in);
            break;
        case 0x682c: // BNX2_HC_RX_TICKS
            DBGOUT(UNKNOWN, "BNX2_HC_RX_TICKS: %08x\n", val_in);
            break;
        case 0x6830: // BNX2_HC_TX_TICKS
            DBGOUT(UNKNOWN, "BNX2_HC_TX_TICKS: %08x\n", val_in);
            break;
        case 0x6834: // BNX2_HC_COM_TICKS
            DBGOUT(UNKNOWN, "BNX2_HC_COM_TICKS: %08x\n", val_in);
            break;
        case 0x6838: // BNX2_HC_CMD_TICKS
            DBGOUT(UNKNOWN, "BNX2_HC_CMD_TICKS: %08x\n", val_in);
            break;
        case 0x6844: // BNX2_HC_STATS_TICKS
            DBGOUT(UNKNOWN, "BNX2_HC_STATS_TICKS: %08x\n", val_in);
            break;
        default:
            if ((reg &~ 0xff) == 0x167c00) { // HOST_VIEW_SHMEM_BASE
                if ((reg & 0xff) == 0x04) { // BNX2_DRV_MB
                    memcpy(d->bnx2_nvram + (reg & 0xff) + 4, &val_in, 4);
                }
                DBGOUT(UNKNOWN, "...SHMEM write %04x@%02x\n", val_in, reg & 0xff);
                memcpy(d->bnx2_nvram + (reg & 0xff), &val_in, 4);
                if ((reg & 0xff) == 0x04) { // on BNX2_FW_MB write update BNX2_DRV_MB
                    memcpy(&val_in, d->bnx2_nvram + 0x08, 4);
                    val_in &= ~0x00ff0000; // BNX2_FW_MSG_STATUS_MASK set to BNX2_FW_MSG_STATUS_OK
                    memcpy(d->bnx2_nvram + 0x08, &val_in, 4);
                }
                break;
            } else if ((reg &~ 0xfff) == 0x45000) { // BNX2_TXP_CPU_MODE
                reg &= 0xfff;
                d->cpu_txp[reg >> 2] = val_in;
                DBGOUT(UNKNOWN, "TXP_CPU_MODE: %08x @ %03x\n", val_in, reg);
                return;
            } else if ((reg &~ 0xfff) == 0x85000) { // BNX2_TPAT_CPU_MODE
                reg &= 0xfff;
                d->cpu_tpat[reg >> 2] = val_in;
                DBGOUT(UNKNOWN, "TPAT_CPU_MODE: %08x @ %03x\n", val_in, reg);
                return;
            } else if ((reg &~ 0xfff) == 0xc5000) { // BNX2_RXP_CPU_MODE
                reg &= 0xfff;
                d->cpu_rxp[reg >> 2] = val_in;
                DBGOUT(UNKNOWN, "RXP_CPU_MODE: %08x @ %03x\n", val_in, reg);
                return;
            } else if ((reg &~ 0xfff) == 0x105000) { // BNX2_COM_CPU_MODE
                reg &= 0xfff;
                d->cpu_com[reg >> 2] = val_in;
                DBGOUT(UNKNOWN, "COM_CPU_MODE: %08x @ %03x\n", val_in, reg);
                return;
            } else if ((reg &~ 0xfff) == 0x185000) { // BNX2_TPAT_CP_MODE
                reg &= 0xfff;
                d->cpu_cp[reg >> 2] = val_in;
                DBGOUT(UNKNOWN, "TPAT_CP_CPU_MODE: %08x @ %03x\n", val_in, reg);
                return;
            }
            else if ((reg &~ 0xfff) == 0x60000) { // BNX2_TXP_SCRATCH
                DBGOUT(UNKNOWN, "TXP_SCRATCH: %08x @ %03x\n", val_in, reg & 0xfff);
                fwrite(&val_in, 4, 1, d->fp[2]);
                break;
            } else if ((reg &~ 0xfff) == 0xa0000) { // BNX2_TPAT_SCRATCH
                DBGOUT(UNKNOWN, "TPAT_SCRATCH: %08x @ %03x\n", val_in, reg & 0xfff);
                fwrite(&val_in, 4, 1, d->fp[4]);
                break;
            } else if ((reg &~ 0xfff) == 0x1a0000) { // BNX2_CP_SCRATCH
                DBGOUT(UNKNOWN, "CP_SCRATCH: %08x @ %03x\n", val_in, reg & 0xfff);
                fwrite(&val_in, 4, 1, d->fp[7]);
                break;
            } else if ((reg &~ 0xfff) == 0x120000) { // BNX2_COM_SCRATCH
                DBGOUT(UNKNOWN, "COM_SCRATCH: %08x @ %03x\n", val_in, reg & 0xfff);
                fwrite(&val_in, 4, 1, d->fp[5]);
                break;
            } else if ((reg &~ 0x7bff) == 0x160000) { // BNX2_MCP_SCRATCH
                DBGOUT(UNKNOWN, "MCP_SCRATCH: %08x @ %03x\n", val_in, reg & 0xbff);
                fwrite(&val_in, 4, 1, d->fp[6]);
                break;
            } else if ((reg &~ 0xfff) == 0xe0000) { // BNX2_RXP_SCRATCH
                DBGOUT(UNKNOWN, "RXP_SCRATCH: %08x @ %03x\n", val_in, reg & 0xfff);
                fwrite(&val_in, 4, 1, d->fp[3]);
                break;
            }
            DBGOUT(UNKNOWN, "PCI write addr=0x%08x val=0x%02x reg=%x\n", addr, val_in, reg);
            break;
        }
    } else if (addr == 0x78) {
        switch (val_in) {
            case 0xb4: // BNX2_PCICFG_DEVICE_CONTROL
            case 0x0408:
            case 0x0418: // BNX2_PCI_SWAP_DIAG0
            case 0x0800:
            case 0x0808: // BNX2_MISC_ID
            case 0x0810:
            case 0x0814: // BNX2_MISC_ENABLE_CLR_BITS
            case 0x08c8:
            case 0x08e8: // BNX2_MISC_PPIO_EVENT
            case 0x08ec: // BNX2_MISC_DUAL_MEDIA_CTRL
            case 0x0c08:
            case 0x1008:
            case 0x100c:
            case 0x1010:
            case 0x1014:
            case 0x1400:
            case 0x1404:
            case 0x1408:
            case 0x1410:
            case 0x1414:
            case 0x1498:
            case 0x149c:
            case 0x14ac:
            case 0x14c4:
            case 0x14c8:
            case 0x14d0:
            case 0x14d4:
            case 0x14d8:
            case 0x14dc:
            case 0x14e0:
            case 0x14e4:
            case 0x14e8:
            case 0x14ec:
            case 0x1820:
            case 0x2800:
            case 0x2808:
            case 0x2830:
            case 0x2834:
            case 0x2838:
            case 0x283c:
            case 0x3c08:
            case 0x3c1c:
            case 0x3c20:
            case 0x4448: // BUFMGR_TX_DMA_ALLOC_RESP
            case 0x5008:
            case 0x6400:
            case 0x640c:
            case 0x6410: // BNX2_NVM_READ
            case 0x6414: // BNX2_NVM_CFG1
            case 0x6420:
            case 0x6424:
            case 0x6800:
            case 0x680c:
            case 0x6810:
            case 0x6814:
            case 0x6820:
            case 0x6824:
            case 0x6828:
            case 0x682c:
            case 0x6830:
            case 0x6834:
            case 0x6838:
            case 0x6844:
            case 0x1400a0: // BNX2_MCP_TOE_ID
                break;
            default:
                if ((val_in &~ 0xff) == 0x167c00 ||
                    (val_in &~ 0xfff) == 0x45000 ||
                    (val_in &~ 0xfff) == 0xc5000 ||
                    (val_in &~ 0xfff) == 0x60000 ||
                    (val_in &~ 0xfff) == 0x85000 ||
                    (val_in &~ 0xfff) == 0x105000 ||
                    (val_in &~ 0xfff) == 0x185000 ||
                    (val_in &~ 0xfff) == 0xa0000 ||
                    (val_in &~ 0xfff) == 0x1a0000 ||
                    (val_in &~ 0xfff) == 0x120000 ||
                    (val_in &~ 0xfff) == 0x160000 ||
                    (val_in &~ 0xfff) == 0xe0000) {
                    break;
                }
                DBGOUT(UNKNOWN, "PCI write addr=0x%08x val=0x%02x\n", addr, val_in);
        }
    } else if (addr == 0x68) { // BNX2_PCICFG_MISC_CONFIG
        DBGOUT(UNKNOWN, "BNX2_PCICFG_MISC_CONFIG: %08x\n", val);
    } else if (addr == 0x84) { // BNX2_PCICFG_INT_ACK_CMD
        DBGOUT(UNKNOWN, "BNX2_PCICFG_INT_ACK_CMD: %08x\n", val_in);
    } else if (addr == 0x90) { // BNX2_PCICFG_MAILBOX_QUEUE_ADDR
        DBGOUT(UNKNOWN, "BNX2_PCICFG_MAILBOX_QUEUE_ADDR: %08x\n", val_in);
    } else if (addr == 0x94) { // BNX2_PCICFG_MAILBOX_QUEUE_DATA
        DBGOUT(UNKNOWN, "BNX2_PCICFG_MAILBOX_QUEUE_DATA: %08x\n", val_in);
    } else {
        DBGOUT(UNKNOWN, "PCI write addr=0x%08x val=0x%02x\n", addr, val_in);
    }

    pci_default_write_config(pci_dev, addr, val_in, l);
    return;

#if 0
    if (ranges_overlap(addr, l, PCI_BASE_ADDRESS_0, 24) ||
        ranges_overlap(addr, l, PCI_ROM_ADDRESS, 4) ||
        ranges_overlap(addr, l, PCI_ROM_ADDRESS1, 4) ||
        range_covers_byte(addr, l, PCI_COMMAND))
        pci_update_mappings(d);

    if (range_covers_byte(addr, l, PCI_COMMAND)) {
//        pci_update_irq_disabled(d, was_irq_disabled);
        memory_region_set_enabled(&d->bus_master_enable_region,
                                  pci_get_word(d->config + PCI_COMMAND)
                                    & PCI_COMMAND_MASTER);
    }
#endif
}


static Property e1000_properties[] = {
    DEFINE_NIC_PROPERTIES(E1000State, conf),
    DEFINE_PROP_BIT("autonegotiation", E1000State,
                    compat_flags, E1000_FLAG_AUTONEG_BIT, true),
    DEFINE_PROP_BIT("mitigation", E1000State,
                    compat_flags, E1000_FLAG_MIT_BIT, true),
    DEFINE_PROP_END_OF_LIST(),
};

typedef struct E1000Info {
    const char *name;
    uint16_t   device_id;
    uint8_t    revision;
    uint16_t   phy_id2;
} E1000Info;

static void e1000_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
    //E1000BaseClass *e = E1000_DEVICE_CLASS(klass);
    const E1000Info *info = data;

    k->init = pci_e1000_init;
    k->exit = pci_e1000_uninit;
    k->romfile = "bcm5709.rom";
    k->vendor_id = 0x14e4;
    k->device_id = info->device_id;
    k->revision = info->revision;
    k->config_read = bcm5709_read_config;
    k->config_write = bcm5709_write_config;
    k->class_id = PCI_CLASS_NETWORK_ETHERNET;
    set_bit(DEVICE_CATEGORY_NETWORK, dc->categories);
    dc->desc = "Broadcom Nextreme II";
    dc->reset = qdev_e1000_reset;
    dc->vmsd = &vmstate_e1000;
    dc->props = e1000_properties;
}

static const TypeInfo e1000_base_info = {
    .name          = TYPE_E1000_BASE,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(E1000State),
    .class_size    = sizeof(E1000BaseClass),
    .abstract      = true,
};

static const E1000Info e1000_devices[] = {
    {
        .name      = "bcm5709",
        .device_id = 0x1639,
        .revision  = 0x00,
    },
};

static void bcm5709_register_types(void)
{
    int i;

    type_register_static(&e1000_base_info);
    for (i = 0; i < ARRAY_SIZE(e1000_devices); i++) {
        const E1000Info *info = &e1000_devices[i];
        TypeInfo type_info = {};

        type_info.name = info->name;
        type_info.parent = TYPE_E1000_BASE;
        type_info.class_data = (void *)info;
        type_info.class_init = e1000_class_init;

        type_register(&type_info);
    }
}

type_init(bcm5709_register_types)
