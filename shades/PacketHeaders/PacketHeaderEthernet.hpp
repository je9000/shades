#ifndef PacketHeaderEthernet_h
#define PacketHeaderEthernet_h

#include <array>
#include <unordered_map>
#include <string>
#include <random>

#include "HexDump.hpp"
#include "PacketHeader.hpp"
#include "PacketBuffer.hpp"
#include "BufferOffsetType.hpp"

const uint8_t ETHERNET_MULTICAST_BIT = 0b1;
static const int ETHERNET_MAC_SIZE = 6;
typedef std::array<unsigned char, ETHERNET_MAC_SIZE> EthernetAddressActual;

class EthernetAddress {
public:
    EthernetAddress() {
        std::fill(address.begin(), address.end(), 0);
    }
    
    EthernetAddress(const std::string_view src) {
        address = mac_from_string(src);
    }
    
    static EthernetAddressActual make_random_address() {
        std::random_device rd;
        std::minstd_rand re(rd()); // fast
        EthernetAddressActual ea;
        
        for(size_t i = 0; i < ea.max_size(); i++) ea[i] = re();
        
        ea[0] |= 0x02; // Set locally administered bit
        ea[0] &= ~ETHERNET_MULTICAST_BIT; // Clear mutlicast bit
        return ea;
    }

    static EthernetAddressActual mac_from_string(const std::string_view src) {
        EthernetAddressActual addr;
        if (src.size() != 17) throw std::runtime_error("Invalid address format");
        for (int i = 0; i < addr.size(); i++) {
            off_t offset = i * 3;
            addr[i] = std::strtoul(&src.at(offset), nullptr, 16);
        }
        return addr;
    }
    
    void operator=(const std::string_view src) {
        address = mac_from_string(src);
    }
    
    bool operator==(const EthernetAddress &other) {
        return address == other.address;
    }
    
    bool operator!=(const EthernetAddress &other) {
        return address != other.address;
    }
    
    uint8_t &operator[](size_t offset) {
        return address[offset];
    }
    
    uint8_t *data() {
        return address.data();
    }
    
    static size_t size() {
        return sizeof(address);
    }
    
    EthernetAddressActual address;
};

const EthernetAddress ETHER_ADDR_BROADCAST("FF:FF:FF:FF:FF:FF");
const EthernetAddress ETHER_ADDR_ZERO("00:00:00:00:00:00");

class PacketHeaderEthernetTypes {
private:
    std::unordered_map<uint16_t, const char *> ether_types;
    const char *unknown = "UNKNOWN";
public:
    std::string operator()(uint16_t n) {
        auto found = ether_types.find(n);
        if (found == ether_types.end()) return unknown;
        return found->second;
    }
    PacketHeaderEthernetTypes() {
        ether_types[0x0004] = "ETHERTYPE_8023";
        ether_types[0x0200] = "ETHERTYPE_PUP";
        ether_types[0x0200] = "ETHERTYPE_PUPAT";
        ether_types[0x0500] = "ETHERTYPE_SPRITE";
        ether_types[0x0600] = "ETHERTYPE_NS";
        ether_types[0x0601] = "ETHERTYPE_NSAT";
        ether_types[0x0660] = "ETHERTYPE_DLOG1";
        ether_types[0x0661] = "ETHERTYPE_DLOG2";
        ether_types[0x0800] = "ETHERTYPE_IP";
        ether_types[0x0801] = "ETHERTYPE_X75";
        ether_types[0x0802] = "ETHERTYPE_NBS";
        ether_types[0x0803] = "ETHERTYPE_ECMA";
        ether_types[0x0804] = "ETHERTYPE_CHAOS";
        ether_types[0x0805] = "ETHERTYPE_X25";
        ether_types[0x0806] = "ETHERTYPE_ARP";
        ether_types[0x0807] = "ETHERTYPE_NSCOMPAT";
        ether_types[0x0808] = "ETHERTYPE_FRARP";
        ether_types[0x0900] = "ETHERTYPE_UBDEBUG";
        ether_types[0x0A00] = "ETHERTYPE_IEEEPUP";
        ether_types[0x0A01] = "ETHERTYPE_IEEEPUPAT";
        ether_types[0x0BAD] = "ETHERTYPE_VINES";
        ether_types[0x0BAE] = "ETHERTYPE_VINESLOOP";
        ether_types[0x0BAF] = "ETHERTYPE_VINESECHO";
        ether_types[0x1000] = "ETHERTYPE_TRAIL";
        ether_types[16] = "ETHERTYPE_NTRAILER";
        ether_types[0x1234] = "ETHERTYPE_DCA";
        ether_types[0x1600] = "ETHERTYPE_VALID";
        ether_types[0x1989] = "ETHERTYPE_DOGFIGHT";
        ether_types[0x1995] = "ETHERTYPE_RCL";
        ether_types[0x3C00] = "ETHERTYPE_NBPVCD";
        ether_types[0x3C01] = "ETHERTYPE_NBPSCD";
        ether_types[0x3C02] = "ETHERTYPE_NBPCREQ";
        ether_types[0x3C03] = "ETHERTYPE_NBPCRSP";
        ether_types[0x3C04] = "ETHERTYPE_NBPCC";
        ether_types[0x3C05] = "ETHERTYPE_NBPCLREQ";
        ether_types[0x3C06] = "ETHERTYPE_NBPCLRSP";
        ether_types[0x3C07] = "ETHERTYPE_NBPDG";
        ether_types[0x3C08] = "ETHERTYPE_NBPDGB";
        ether_types[0x3C09] = "ETHERTYPE_NBPCLAIM";
        ether_types[0x3C0A] = "ETHERTYPE_NBPDLTE";
        ether_types[0x3C0B] = "ETHERTYPE_NBPRAS";
        ether_types[0x3C0C] = "ETHERTYPE_NBPRAR";
        ether_types[0x3C0D] = "ETHERTYPE_NBPRST";
        ether_types[0x4242] = "ETHERTYPE_PCS";
        ether_types[0x424C] = "ETHERTYPE_IMLBLDIAG";
        ether_types[0x4321] = "ETHERTYPE_DIDDLE";
        ether_types[0x4C42] = "ETHERTYPE_IMLBL";
        ether_types[0x5208] = "ETHERTYPE_SIMNET";
        ether_types[0x6000] = "ETHERTYPE_DECEXPER";
        ether_types[0x6001] = "ETHERTYPE_MOPDL";
        ether_types[0x6002] = "ETHERTYPE_MOPRC";
        ether_types[0x6003] = "ETHERTYPE_DECnet";
        //ether_types[ETHERTYPE_DECnet] = "ETHERTYPE_DN";
        ether_types[0x6004] = "ETHERTYPE_LAT";
        ether_types[0x6005] = "ETHERTYPE_DECDIAG";
        ether_types[0x6006] = "ETHERTYPE_DECCUST";
        ether_types[0x6007] = "ETHERTYPE_SCA";
        ether_types[0x6008] = "ETHERTYPE_AMBER";
        ether_types[0x6009] = "ETHERTYPE_DECMUMPS";
        ether_types[0x6558] = "ETHERTYPE_TRANSETHER";
        ether_types[0x6559] = "ETHERTYPE_RAWFR";
        ether_types[0x7000] = "ETHERTYPE_UBDL";
        ether_types[0x7001] = "ETHERTYPE_UBNIU";
        ether_types[0x7002] = "ETHERTYPE_UBDIAGLOOP";
        ether_types[0x7003] = "ETHERTYPE_UBNMC";
        ether_types[0x7005] = "ETHERTYPE_UBBST";
        ether_types[0x7007] = "ETHERTYPE_OS9";
        ether_types[0x7009] = "ETHERTYPE_OS9NET";
        ether_types[0x7030] = "ETHERTYPE_RACAL";
        ether_types[0x7031] = "ETHERTYPE_PRIMENTS";
        ether_types[0x7034] = "ETHERTYPE_CABLETRON";
        ether_types[0x8003] = "ETHERTYPE_CRONUSVLN";
        ether_types[0x8004] = "ETHERTYPE_CRONUS";
        ether_types[0x8005] = "ETHERTYPE_HP";
        ether_types[0x8006] = "ETHERTYPE_NESTAR";
        ether_types[0x8008] = "ETHERTYPE_ATTSTANFORD";
        ether_types[0x8010] = "ETHERTYPE_EXCELAN";
        ether_types[0x8013] = "ETHERTYPE_SG_DIAG";
        ether_types[0x8014] = "ETHERTYPE_SG_NETGAMES";
        ether_types[0x8015] = "ETHERTYPE_SG_RESV";
        ether_types[0x8016] = "ETHERTYPE_SG_BOUNCE";
        ether_types[0x8019] = "ETHERTYPE_APOLLODOMAIN";
        ether_types[0x802E] = "ETHERTYPE_TYMSHARE";
        ether_types[0x802F] = "ETHERTYPE_TIGAN";
        ether_types[0x8035] = "ETHERTYPE_REVARP";
        ether_types[0x8036] = "ETHERTYPE_AEONIC";
        ether_types[0x8037] = "ETHERTYPE_IPXNEW";
        ether_types[0x8038] = "ETHERTYPE_LANBRIDGE";
        ether_types[0x8039] = "ETHERTYPE_DSMD";
        ether_types[0x803A] = "ETHERTYPE_ARGONAUT";
        ether_types[0x803B] = "ETHERTYPE_VAXELN";
        ether_types[0x803C] = "ETHERTYPE_DECDNS";
        ether_types[0x803D] = "ETHERTYPE_ENCRYPT";
        ether_types[0x803E] = "ETHERTYPE_DECDTS";
        ether_types[0x803F] = "ETHERTYPE_DECLTM";
        ether_types[0x8040] = "ETHERTYPE_DECNETBIOS";
        ether_types[0x8041] = "ETHERTYPE_DECLAST";
        ether_types[0x8044] = "ETHERTYPE_PLANNING";
        ether_types[0x8048] = "ETHERTYPE_DECAM";
        ether_types[0x8049] = "ETHERTYPE_EXPERDATA";
        ether_types[0x805B] = "ETHERTYPE_VEXP";
        ether_types[0x805C] = "ETHERTYPE_VPROD";
        ether_types[0x805D] = "ETHERTYPE_ES";
        ether_types[0x8060] = "ETHERTYPE_LITTLE";
        ether_types[0x8062] = "ETHERTYPE_COUNTERPOINT";
        ether_types[0x8067] = "ETHERTYPE_VEECO";
        ether_types[0x8068] = "ETHERTYPE_GENDYN";
        ether_types[0x8069] = "ETHERTYPE_ATT";
        ether_types[0x806A] = "ETHERTYPE_AUTOPHON";
        ether_types[0x806C] = "ETHERTYPE_COMDESIGN";
        ether_types[0x806D] = "ETHERTYPE_COMPUGRAPHIC";
        ether_types[0x807A] = "ETHERTYPE_MATRA";
        ether_types[0x807B] = "ETHERTYPE_DDE";
        ether_types[0x807C] = "ETHERTYPE_MERIT";
        ether_types[0x8080] = "ETHERTYPE_VLTLMAN";
        ether_types[0x809B] = "ETHERTYPE_ATALK";
        //ether_types[ETHERTYPE_ATALK] = "ETHERTYPE_AT";
        //ether_types[ETHERTYPE_ATALK] = "ETHERTYPE_APPLETALK";
        ether_types[0x809F] = "ETHERTYPE_SPIDER";
        ether_types[0x80C6] = "ETHERTYPE_PACER";
        ether_types[0x80C7] = "ETHERTYPE_APPLITEK";
        ether_types[0x80D5] = "ETHERTYPE_SNA";
        ether_types[0x80DD] = "ETHERTYPE_VARIAN";
        ether_types[0x80F2] = "ETHERTYPE_RETIX";
        ether_types[0x80F3] = "ETHERTYPE_AARP";
        ether_types[0x80F7] = "ETHERTYPE_APOLLO";
        ether_types[0x8100] = "ETHERTYPE_VLAN";
        ether_types[0x8102] = "ETHERTYPE_BOFL";
        ether_types[0x8103] = "ETHERTYPE_WELLFLEET";
        ether_types[0x812B] = "ETHERTYPE_TALARIS";
        ether_types[0x8130] = "ETHERTYPE_WATERLOO";
        ether_types[0x8130] = "ETHERTYPE_HAYES";
        ether_types[0x8131] = "ETHERTYPE_VGLAB";
        ether_types[0x8137] = "ETHERTYPE_IPX";
        ether_types[0x8138] = "ETHERTYPE_NOVELL";
        ether_types[0x813F] = "ETHERTYPE_MUMPS";
        ether_types[0x8145] = "ETHERTYPE_AMOEBA";
        ether_types[0x8146] = "ETHERTYPE_FLIP";
        ether_types[0x8147] = "ETHERTYPE_VURESERVED";
        ether_types[0x8148] = "ETHERTYPE_LOGICRAFT";
        ether_types[0x8149] = "ETHERTYPE_NCD";
        ether_types[0x814A] = "ETHERTYPE_ALPHA";
        ether_types[0x814C] = "ETHERTYPE_SNMP";
        ether_types[0x814F] = "ETHERTYPE_TEC";
        ether_types[0x8150] = "ETHERTYPE_RATIONAL";
        ether_types[0x817D] = "ETHERTYPE_XTP";
        ether_types[0x817E] = "ETHERTYPE_SGITW";
        ether_types[0x8180] = "ETHERTYPE_HIPPI_FP";
        ether_types[0x8181] = "ETHERTYPE_STP";
        ether_types[0x818D] = "ETHERTYPE_MOTOROLA";
        ether_types[0x8191] = "ETHERTYPE_NETBEUI";
        ether_types[0x8390] = "ETHERTYPE_ACCTON";
        ether_types[0x852B] = "ETHERTYPE_TALARISMC";
        ether_types[0x8582] = "ETHERTYPE_KALPANA";
        ether_types[0x86DB] = "ETHERTYPE_SECTRA";
        ether_types[0x86DD] = "ETHERTYPE_IPV6";
        ether_types[0x86DE] = "ETHERTYPE_DELTACON";
        ether_types[0x86DF] = "ETHERTYPE_ATOMIC";
        ether_types[0x8739] = "ETHERTYPE_RDP";
        ether_types[0x873A] = "ETHERTYPE_MICP";
        ether_types[0x876B] = "ETHERTYPE_TCPCOMP";
        ether_types[0x876C] = "ETHERTYPE_IPAS";
        ether_types[0x876D] = "ETHERTYPE_SECUREDATA";
        ether_types[0x8808] = "ETHERTYPE_FLOWCONTROL";
        ether_types[0x8809] = "ETHERTYPE_SLOW";
        ether_types[0x880B] = "ETHERTYPE_PPP";
        ether_types[0x8820] = "ETHERTYPE_HITACHI";
        ether_types[0x8847] = "ETHERTYPE_MPLS";
        ether_types[0x8848] = "ETHERTYPE_MPLS_MCAST";
        ether_types[0x8856] = "ETHERTYPE_AXIS";
        ether_types[0x8863] = "ETHERTYPE_PPPOEDISC";
        ether_types[0x8864] = "ETHERTYPE_PPPOE";
        ether_types[0x8888] = "ETHERTYPE_LANPROBE";
        ether_types[0x888E] = "ETHERTYPE_PAE";
        ether_types[0x88A2] = "ETHERTYPE_AOE";
        ether_types[0x88A8] = "ETHERTYPE_QINQ";
        ether_types[0x88CC] = "ETHERTYPE_LLDP";
        ether_types[0x9000] = "ETHERTYPE_LOOPBACK";
        //ether_types[ETHERTYPE_LOOPBACK] = "ETHERTYPE_LBACK";
        ether_types[0x9001] = "ETHERTYPE_XNSSM";
        ether_types[0x9002] = "ETHERTYPE_TCPSM";
        ether_types[0x9003] = "ETHERTYPE_BCLOOP";
        ether_types[0xAAAA] = "ETHERTYPE_DEBNI";
        ether_types[0xFAF5] = "ETHERTYPE_SONIX";
        ether_types[0xFF00] = "ETHERTYPE_VITAL";
        ether_types[0xFFFF] = "ETHERTYPE_MAX";
    }
};
static PacketHeaderEthernetTypes ETHERNET_TYPE_INFO;

namespace ETHERTYPE {
    enum ETHERTYPE {
        ETHERNET = 0x01,
        _8023 = 0x0004,
        PUP = 0x0200,
        PUPAT = 0x0200,
        SPRITE = 0x0500,
        NS = 0x0600,
        NSAT = 0x0601,
        DLOG1 = 0x0660,
        DLOG2 = 0x0661,
        IP = 0x0800,
        X75 = 0x0801,
        NBS = 0x0802,
        ECMA = 0x0803,
        CHAOS = 0x0804,
        X25 = 0x0805,
        ARP = 0x0806,
        NSCOMPAT = 0x0807,
        FRARP = 0x0808,
        UBDEBUG = 0x0900,
        IEEEPUP = 0x0A00,
        IEEEPUPAT = 0x0A01,
        VINES = 0x0BAD,
        VINESLOOP = 0x0BAE,
        VINESECHO = 0x0BAF,
        TRAIL = 0x1000,
        NTRAILER = 16,
        DCA = 0x1234,
        VALID = 0x1600,
        DOGFIGHT = 0x1989,
        RCL = 0x1995,
        NBPVCD = 0x3C00,
        NBPSCD = 0x3C01,
        NBPCREQ = 0x3C02,
        NBPCRSP = 0x3C03,
        NBPCC = 0x3C04,
        NBPCLREQ = 0x3C05,
        NBPCLRSP = 0x3C06,
        NBPDG = 0x3C07,
        NBPDGB = 0x3C08,
        NBPCLAIM = 0x3C09,
        NBPDLTE = 0x3C0A,
        NBPRAS = 0x3C0B,
        NBPRAR = 0x3C0C,
        NBPRST = 0x3C0D,
        PCS = 0x4242,
        IMLBLDIAG = 0x424C,
        DIDDLE = 0x4321,
        IMLBL = 0x4C42,
        SIMNET = 0x5208,
        DECEXPER = 0x6000,
        MOPDL = 0x6001,
        MOPRC = 0x6002,
        DECnet = 0x6003,
        DN = DECnet,
        LAT = 0x6004,
        DECDIAG = 0x6005,
        DECCUST = 0x6006,
        SCA = 0x6007,
        AMBER = 0x6008,
        DECMUMPS = 0x6009,
        TRANSETHER = 0x6558,
        RAWFR = 0x6559,
        UBDL = 0x7000,
        UBNIU = 0x7001,
        UBDIAGLOOP = 0x7002,
        UBNMC = 0x7003,
        UBBST = 0x7005,
        OS9 = 0x7007,
        OS9NET = 0x7009,
        RACAL = 0x7030,
        PRIMENTS = 0x7031,
        CABLETRON = 0x7034,
        CRONUSVLN = 0x8003,
        CRONUS = 0x8004,
        HP = 0x8005,
        NESTAR = 0x8006,
        ATTSTANFORD = 0x8008,
        EXCELAN = 0x8010,
        SG_DIAG = 0x8013,
        SG_NETGAMES = 0x8014,
        SG_RESV = 0x8015,
        SG_BOUNCE = 0x8016,
        APOLLODOMAIN = 0x8019,
        TYMSHARE = 0x802E,
        TIGAN = 0x802F,
        REVARP = 0x8035,
        AEONIC = 0x8036,
        IPXNEW = 0x8037,
        LANBRIDGE = 0x8038,
        DSMD = 0x8039,
        ARGONAUT = 0x803A,
        VAXELN = 0x803B,
        DECDNS = 0x803C,
        ENCRYPT = 0x803D,
        DECDTS = 0x803E,
        DECLTM = 0x803F,
        DECNETBIOS = 0x8040,
        DECLAST = 0x8041,
        PLANNING = 0x8044,
        DECAM = 0x8048,
        EXPERDATA = 0x8049,
        VEXP = 0x805B,
        VPROD = 0x805C,
        ES = 0x805D,
        LITTLE = 0x8060,
        COUNTERPOINT = 0x8062,
        VEECO = 0x8067,
        GENDYN = 0x8068,
        ATT = 0x8069,
        AUTOPHON = 0x806A,
        COMDESIGN = 0x806C,
        COMPUGRAPHIC = 0x806D,
        MATRA = 0x807A,
        DDE = 0x807B,
        MERIT = 0x807C,
        VLTLMAN = 0x8080,
        ATALK = 0x809B,
        AT = ATALK,
        APPLETALK = ATALK,
        SPIDER = 0x809F,
        PACER = 0x80C6,
        APPLITEK = 0x80C7,
        SNA = 0x80D5,
        VARIAN = 0x80DD,
        RETIX = 0x80F2,
        AARP = 0x80F3,
        APOLLO = 0x80F7,
        VLAN = 0x8100,
        BOFL = 0x8102,
        WELLFLEET = 0x8103,
        TALARIS = 0x812B,
        WATERLOO = 0x8130,
        HAYES = 0x8130,
        VGLAB = 0x8131,
        IPX = 0x8137,
        NOVELL = 0x8138,
        MUMPS = 0x813F,
        AMOEBA = 0x8145,
        FLIP = 0x8146,
        VURESERVED = 0x8147,
        LOGICRAFT = 0x8148,
        NCD = 0x8149,
        ALPHA = 0x814A,
        SNMP = 0x814C,
        TEC = 0x814F,
        RATIONAL = 0x8150,
        XTP = 0x817D,
        SGITW = 0x817E,
        HIPPI_FP = 0x8180,
        STP = 0x8181,
        MOTOROLA = 0x818D,
        NETBEUI = 0x8191,
        ACCTON = 0x8390,
        TALARISMC = 0x852B,
        KALPANA = 0x8582,
        SECTRA = 0x86DB,
        IPV6 = 0x86DD,
        DELTACON = 0x86DE,
        ATOMIC = 0x86DF,
        RDP = 0x8739,
        MICP = 0x873A,
        TCPCOMP = 0x876B,
        IPAS = 0x876C,
        SECUREDATA = 0x876D,
        FLOWCONTROL = 0x8808,
        SLOW = 0x8809,
        PPP = 0x880B,
        HITACHI = 0x8820,
        MPLS = 0x8847,
        MPLS_MCAST = 0x8848,
        AXIS = 0x8856,
        PPPOEDISC = 0x8863,
        PPPOE = 0x8864,
        LANPROBE = 0x8888,
        PAE = 0x888E,
        AOE = 0x88A2,
        QINQ = 0x88A8,
        LLDP = 0x88CC,
        LOOPBACK = 0x9000,
        LBACK = LOOPBACK,
        XNSSM = 0x9001,
        TCPSM = 0x9002,
        BCLOOP = 0x9003,
        DEBNI = 0xAAAA,
        SONIX = 0xFAF5,
        VITAL = 0xFF00,
        MAX = 0xFFFF
    };
} // namespace ETHERTYPES

class PacketHeaderEthernet : public PacketHeader {
public:
    BufferOffsetType<0, EthernetAddress> dest;
    BufferOffsetType<6, EthernetAddress> source;
    //BufferOffsetType<12, uint16_t> tag;
    BufferOffsetType<12, uint16_t> ether_type;
    
    PacketHeaderEthernet(PacketBufferOffset source_pbo) :
        PacketHeader(source_pbo),
        dest(*this),
        source(*this),
        ether_type(*this)
    {}
    
    void check() const {
        if (ether_type() <= 1500) throw invalid_packet("Raw IEEE 802.3, 802.2 not supported");
        if (ether_type() <= 1536 /* && > 1500 */) throw invalid_packet("Invalid ethertype");
    };
    
    void print(std::ostream &) const;
    
    size_t header_size() const {
        return 14;
    }
    
    virtual std::unique_ptr<PacketHeader> recalculate_next_header() const;
    
    void build(const EthernetAddress &src_eth, const EthernetAddress &dest_eth, const ETHERTYPE::ETHERTYPE type) {
        dest = dest_eth;
        source = src_eth;
        ether_type = type;
    }
};

std::ostream &operator<<(std::ostream &os, const EthernetAddress &ea) {
    os << HexDump<EthernetAddressActual>(ea.address, ':', 0);
    return os;
}

void PacketHeaderEthernet::print(std::ostream &os) const {
    os << "Ethernet frame:\n";
    os << " Dest MAC: " << dest() << "\n";
    os << " Source MAC: " << source() << "\n";
    os << " EtherType: " << ether_type() << " (" << ETHERNET_TYPE_INFO(ether_type()) << ")\n";
    //os << " Tag: " << tag() << "\n";
    //os << " CRC32: " << crc() << "\n";
}

#endif /* PacketHeaderEthernet_h */
