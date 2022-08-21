// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2020 The PIVX developers
// Copyright (c) 2021 The DECENOMY Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "chainparamsseeds.h"
#include "consensus/merkle.h"
#include "util.h"
#include "utilstrencodings.h"

#include <boost/assign/list_of.hpp>

#include <assert.h>

#define DISABLED 0x7FFFFFFE;

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.nVersion = nVersion;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of the genesis coinbase cannot
 * be spent as it did not originally exist in the database.
 *
 * CBlock(hash=00000ffd590b14, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=e0028e, nTime=1390095618, nBits=1e0ffff0, nNonce=28917698, vtx=1)
 *   CTransaction(hash=e0028e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d01044c5957697265642030392f4a616e2f3230313420546865204772616e64204578706572696d656e7420476f6573204c6976653a204f76657273746f636b2e636f6d204973204e6f7720416363657074696e6720426974636f696e73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0xA9037BAC7050C479B121CF)
 *   vMerkleTree: e0028e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "April 18th 2015 Global stocks nosedive";
    const CScript genesisOutputScript = CScript() << ParseHex("04e209a299d9b1483b42c1e827975054b276188cb1b86943ebf9673a955b4bfb466d6ef5167539deac570ebb9df4eb5b256a9dd2a5a9bd44399e16d9bf6fae46c2") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    ( 0,       uint256("0x0000036366895115eba0d9a314a3fc10a3972b82db5413d79e98a4aba1927e46"))
    ( 17901,   uint256("0x02fe1643c757baa442fc350d21b67a97ef1cef845dc546feb849540557c5e4e2"))
    ( 50000,   uint256("0x0ccf4691316246577c9b428849f0369f48cfefd1908483d4a0c1793d930188ff"))
    ( 100000,  uint256("0xfffc2faebe0c4f02cd8e72d8d47cfb1b63c2fb7f1936e652181b08d1794ee222"))
    ( 250000,  uint256("0x12cf3bfe3e849af77ff2a0dee5ece1866b979ac64f7b9b17a06c337fb8bb60d3"))
    ( 500000,  uint256("0x907b9db40d701314a38db5f9180c6a99a3c687880cce416bfeeff0586fa1d764"))
    ( 1000000, uint256("0xa9e79fc2f1791ba095aa5cc603d6d0be059b83cc3ee8077e83eba0571058efb8"))
    ( 1100000, uint256("0x3674d67d7ef1d01db01195d307eec0757b8fa10396b305c8197c93e862a24361"))
    ( 1240000, uint256("0x1c2fb244b499ed13d0b06879d0eab99b4e0c2e092a50852b24bde3c26f128edf"))
    ( 1355000, uint256("0x42ff9269a32fb219c2429c03ca046932c900d1ea314c615fe7e711c158972573"))
    ( 1460000, uint256("0xf0d9c992632d15cb24623c99d2e3a53877da6c444f1f04d0960c47355b9359e8"))
    ( 1490000, uint256("0xbdbeeb7a512f7a31be52237da5c093e2e99cb6bb7c5aeb013b9cf878d6eced49"))
    ( 1500000, uint256("0x0cd0ef16b83e1aefeeaef5524a43d841d3104667e43393b22ece3fe91abdf060"))
    ( 1550000, uint256("0xf73194aeaf958d26133a6be585a6251e88026b6b78138119ca68a947e1c79bc7"))
    ( 1600000, uint256("0x725d470b4ec4fe736c93482eaec8768a3729a9d016dc69b0422f740e141c6583"))
    ( 1650000, uint256("0xc6a4be268f3a618c15a165e8d385322f4335f835c28e789bf245cc031ec964e6"))
    ( 1680000, uint256("0x40d884e834ff793e205492c8dd9bfb5e62fce4344935f017bbbcdce87774f792"))
    ( 1700000, uint256("0xce589c73685ceed50b224a777704773cb699e5312e33653b105af6eb05641020"))
    ( 1710000, uint256("0xf9b3f46d4cf0d3260cc153041eddf132403c8553aa0850c75ef28a0b1a157cae"))
    ( 1726000, uint256("0x1cc402d4c949a5a2be81a0864bbe64697be931dca2f332927edce3e6bfc1fb7e"))
    ( 1736000, uint256("0xb881cbf704c0ee1985eec280ffd1a1c3304c275381d78f16809e2fc5dc3933fd"))
    ( 1740000, uint256("0x2c2730fd9b7ace6b534f0ca2ab0e93ce1744afd015542baf907ed62cba9a4c94"))
    ( 1750000, uint256("0x8942ada7e88fd5f88b0d9a9038110e56aacc27ed32f5ddf5fe02d08169b8c4d9"))
    ( 1758000, uint256("0xfc3d21c40c77c1f816a32f45ea661715b2615db5cdd7f88e285f74272abc63c0"))
    ( 1805000, uint256("0x765a1af36a90b0bcea4e4da917644bfdf86b3587c7bd125efe94a834260015c6"))
    ( 1850000, uint256("0xf9dfa0912231b9343975c2e8a6f2640423576aea361eb746c4299ae9faf9b826"))
    ( 1863000, uint256("0x5e70e779d7d570c312a47fdc63ff75ed5c0b26250f9ec75ac5dfe8df66f83c03"))
    ( 1893000, uint256("0x5daa6dd7f7467756bbacf75aa3036bfd691fcb304e9e43007cbb9fa606daca1a"))
    ( 1900000, uint256("0x4f306c7d8fbe5db2e36520c86fea3d663939a9c241b032c43ab9e6f2c6ef5cf2"))
    ( 1950000, uint256("0x78a36b13adcb22b44e7ed76c33fdb4fd833ee6f4c1baf782b6b886cea1499019"))
    ( 2000000, uint256("0x1c9fa532de3e2a2bb70030100823966d05e79fa0732cdbe86cd6b52c1d8996d3"))
    ( 2040000, uint256("0x6013990ef9fe59390cec3ad971d2f708e94da72ffaa3727f048ee7f5058c1e69"))
    ( 2101000, uint256("0x92875555fad29460ae9d217c0af4b6db322a9d66f398eb31261dda9f7639ee4c"))
    ( 2200000, uint256("0x217412533532bc9e0343d57bfd7b09e883c75a9e65f3473c38e2301ce650a2ef"))
    ( 2300000, uint256("0x08cae3a2ee028904762deb1c1be25a4dc36bd02041bc5b0a2585cfb393534b45"))
    ( 2400000, uint256("0x82fb390724a81b4bd4e72dd2bfafd635149eb3d6e9b8ab1a7b0eb887589de276"))
    ( 2500000, uint256("0x64dc751c6dee45c4a0c5a147058cb2294fb8543aae5c2ebed5a5146dde6f80d2"))
    ( 2600000, uint256("0x76bd2fae5df767a49d639efe7a00805c6a12083a72831c34fd98070a28ed26a4"))
    ( 2700000, uint256("0x42029854253a49dd85e2693eed28bf184eba19b22d9243269f8c31b129cc9c25"))
    ( 2800000, uint256("0x05a0f6e016e934871dd428a7aa3f14daeaef9a4841fd9e42562ff83c7d366495"))
    ( 2900000, uint256("0x2cf18505f16b77d386c61e978a3fae0505ee97068255535f215f7f45e0087b57"));

static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1658005424, // * UNIX timestamp of last checkpoint block
    118128,          // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the UpdateTip debug.log lines)
    1.000        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of
    (0, uint256S("0x0"));

static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1656793445,
    0,
    0.000
    };

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256S("0x0"));

static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1656793446,
    0,
    0.000
    };

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
/**
        // // This is used inorder to mine the genesis block. Once found, we can use the nonce and block hash found to create a valid genesis block
        // /////////////////////////////////////////////////////////////////

         uint32_t nGenesisTime = 1656793447;
         arith_uint256 test;
         bool fNegative;
         bool fOverflow;
         test.SetCompact(0x1e0ffff0, &fNegative, &fOverflow);
         std::cout << "Test threshold: " << test.GetHex() << "\n\n";

         int genesisNonce = 0;
         uint256 TempHashHolding = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
         uint256 BestBlockHash = uint256S("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
         for (int i=0;i<40000000;i++) {
             genesis = CreateGenesisBlock(nGenesisTime, i, 0x1e0ffff0, 1, 0 * COIN);
             //genesis.hashPrevBlock = TempHashHolding;
             consensus.hashGenesisBlock = genesis.GetHash();

             arith_uint256 BestBlockHashArith = UintToArith256(BestBlockHash);
             if (UintToArith256(consensus.hashGenesisBlock) < BestBlockHashArith) {
                 BestBlockHash = consensus.hashGenesisBlock;
                 std::cout << BestBlockHash.GetHex() << " Nonce: " << i << "\n";
                 std::cout << "   PrevBlockHash: " << genesis.hashPrevBlock.GetHex() << "\n";
             }

             TempHashHolding = consensus.hashGenesisBlock;

             if (BestBlockHashArith < test) {
                 genesisNonce = i - 1;
                 break;
             }
             //std::cout << consensus.hashGenesisBlock.GetHex() << "\n";
         }
         std::cout << "\n";
         std::cout << "\n";
         std::cout << "\n";

         std::cout << "hashGenesisBlock to 0x" << BestBlockHash.GetHex() << std::endl;
         std::cout << "Genesis Nonce to " << genesisNonce << std::endl;
         std::cout << "Genesis Merkle 0x" << genesis.hashMerkleRoot.GetHex() << std::endl;

         exit(0);
*/
        // /////////////////////////////////////////////////////////////////

        genesis = CreateGenesisBlock(1393221600, 164482, 0x1e0fffff, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x80251aff18129581f06b3036bda4d571b909389699290deced973ebb580d11c5"));
        assert(genesis.hashMerkleRoot == uint256S("0x80251aff18129581f06b3036bda4d571b909389699290deced973ebb580d11c5"));

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.powLimit   = ~UINT256_ZERO >> 20;
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nBudgetCycleBlocks = 30 * 24 * 60;       // approx. 1 every 30 days
        consensus.nBudgetFeeConfirmations = 6;      // Number of confirmations for the finalization fee
        consensus.nCoinbaseMaturity = 80;
        consensus.nFutureTimeDriftPoW = 10 * 60;  // up to 10 minutes from the past
        consensus.nFutureTimeDriftPoS = 10 * 60;  // up to 10 minutes from the future
        consensus.nMasternodeCountDrift = 20;       // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 68000000 * COIN;
        consensus.nPoolMaxTransactions = 3;
        consensus.nProposalEstablishmentTime = 60 * 60 * 24;    // must be at least a day old to make it into a budget
        consensus.nStakeMinAge = 5 * 60 * 60; // Neutron - 5 hours
        consensus.nStakeMinDepth = 100;
        consensus.nStakeMinDepthV2 = 600;
        consensus.nTargetTimespan = 20 * 60;  // Neutron - every 20mins
        consensus.nTargetTimespanV2 = 20 * 60;  // Neutron - every 20mins
        consensus.nTargetSpacing = 1 * 79; // Neutron - 79 secs
        consensus.nTimeSlotLength = 15;

        // spork keys
        consensus.strSporkPubKey = "042b98d4150746cc5ee1b5a991244f8a2b155630efbfa490fee76202912ed2d6e"
                           "9b6e5c62d424b9f5878ee7aff68e9aa84d10821a33e99de27fed2d77f57247954";
        consensus.strSporkPubKeyOld = "04cc53cdd3e788d3ea9ca63468b9f2bcc2838af920d8e72985739e8ac4159d518"
                           "d1a1597da13b1854d8331def51778aa6a01951cef7763fa4300341f34431bad49";
        consensus.nTime_EnforceNewSporkKey = 0;
        consensus.nTime_RejectOldSporkKey = 0;

         // burn addresses
        consensus.mBurnAddresses = {
            { "", 0 },
            { "", 0 },
            { "", 0 },
        };

        // height-based activations
        consensus.height_last_ZC_AccumCheckpoint    = DISABLED;
        consensus.height_last_ZC_WrappedSerials     = DISABLED;
        consensus.height_start_InvalidUTXOsCheck    = DISABLED;
        consensus.height_start_ZC_InvalidSerials    = DISABLED;
        consensus.height_start_ZC_SerialRangeCheck  = DISABLED;
        consensus.height_ZC_RecalcAccumulators      = DISABLED;

        // Zerocoin-related params
        consensus.ZC_Modulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
                "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
                "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
                "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
                "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
                "31438167899885040445364023527381951378636564391212010397122822120720357";
        consensus.ZC_MaxPublicSpendsPerTx = 637;    // Assume about 220 bytes each input
        consensus.ZC_MaxSpendsPerTx = 7;            // Assume about 20kb each input
        consensus.ZC_MinMintConfirmations = 20;
        consensus.ZC_MinMintFee = 1 * CENT;
        consensus.ZC_MinStakeDepth = 200;
        consensus.ZC_TimeStart = 1893456000;        // 01/01/2030 @ 12:00am (UTC)
        consensus.ZC_WrappedSerialsSupply = 0; //4131563 * COIN;   // zerocoin supply at height_last_ZC_WrappedSerials

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight                   = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight              = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight                    = 1001;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight                 = 1441;
        consensus.vUpgrades[Consensus::UPGRADE_ZC].nActivationHeight                     = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_ZC_V2].nActivationHeight                  = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight                  = 1441;
        consensus.vUpgrades[Consensus::UPGRADE_ZC_PUBLIC].nActivationHeight              = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].nActivationHeight      = 1541;
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].nActivationHeight       = 1641;
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].nActivationHeight = 1741;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].nActivationHeight     = 5001;
        consensus.vUpgrades[Consensus::UPGRADE_MASTERNODE_RANK_V2].nActivationHeight     = 115000;

        consensus.vUpgrades[Consensus::UPGRADE_POS].hashActivationBlock                    = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].hashActivationBlock                 = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].hashActivationBlock                  = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].hashActivationBlock      = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].hashActivationBlock       = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].hashActivationBlock = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].hashActivationBlock     = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_MASTERNODE_RANK_V2].hashActivationBlock     = uint256S("0x0");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0xb2;
        pchMessageStart[1] = 0xd1;
        pchMessageStart[2] = 0xf4;
        pchMessageStart[3] = 0xa3;
        nDefaultPort = 32001;

        vSeeds.push_back(CDNSSeedData("seed", "seed.neutroncoin.com"));
        vSeeds.push_back(CDNSSeedData("seed1", "seed1.neutroncoin.com"));
        vSeeds.push_back(CDNSSeedData("seed2", "seed2.neutroncoin.com"));
        vSeeds.push_back(CDNSSeedData("seed3", "seed3.neutroncoin.com"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 50); // M
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 51); // M
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 231);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x02)(0x2D)(0x25)(0x33).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x02)(0x21)(0x31)(0x2B).convert_to_container<std::vector<unsigned char> >();
        // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x03)(0x99).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));
        //convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main)); // added
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }

};
static CMainParams mainParams;

/**
 * Testnet (v1)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";

        genesis = CreateGenesisBlock(1656793445, 18745, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x80251aff18129581f06b3036bda4d571b909389699290deced973ebb580d11c5"));
        assert(genesis.hashMerkleRoot == uint256S("0x80251aff18129581f06b3036bda4d571b909389699290deced973ebb580d11c5"));

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.powLimit   = ~UINT256_ZERO >> 20;
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nBudgetCycleBlocks = 30 * 24 * 60;       // approx. 1 every 30 days
        consensus.nBudgetFeeConfirmations = 6;      // Number of confirmations for the finalization fee
        consensus.nCoinbaseMaturity = 80;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMasternodeCountDrift = 20;       // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 50000000 * COIN;
        consensus.nPoolMaxTransactions = 3;
        consensus.nProposalEstablishmentTime = 60 * 60 * 24;    // must be at least a day old to make it into a budget
        consensus.nStakeMinAge = 5 * 60 * 60; // Neutron - 5 hours
        consensus.nStakeMinDepth = 100;
        consensus.nStakeMinDepthV2 = 600;
        consensus.nTargetTimespan = 20 * 60;  // Neutron - every 20mins
        consensus.nTargetTimespanV2 = 20 * 60;  // Neutron - every 20mins
        consensus.nTargetSpacing = 1 * 79; // Neutron - 79 secs
        consensus.nTimeSlotLength = 15;

        // spork keys
        consensus.strSporkPubKey = "042b98d4150746cc5ee1b5a991244f8a2b155630efbfa490fee76202912ed2d6e"
                           "9b6e5c62d424b9f5878ee7aff68e9aa84d10821a33e99de27fed2d77f57247954";
        consensus.strSporkPubKeyOld = "042E0E340B40681EEFB7C67B7CBE968E3AB47F4A393E3626E13309CFDC5A1C5D5"
                           "B9537CD3CEBA3B5B1656D2949355CADA0F5EE74C4EDCCBEF84BF80151EF3B0C0A";
        consensus.nTime_EnforceNewSporkKey = 0;
        consensus.nTime_RejectOldSporkKey = 0;

        // height based activations
        consensus.height_last_ZC_AccumCheckpoint    = 999999999;
        consensus.height_last_ZC_WrappedSerials     = 999999999;
        consensus.height_start_InvalidUTXOsCheck    = 999999999;
        consensus.height_start_ZC_InvalidSerials    = 999999999;
        consensus.height_start_ZC_SerialRangeCheck  = 999999999;
        consensus.height_ZC_RecalcAccumulators      = 999999999;

        // Zerocoin-related params
        consensus.ZC_Modulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
                "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
                "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
                "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
                "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
                "31438167899885040445364023527381951378636564391212010397122822120720357";
        consensus.ZC_MaxPublicSpendsPerTx = 637;    // Assume about 220 bytes each input
        consensus.ZC_MaxSpendsPerTx = 7;            // Assume about 20kb each input
        consensus.ZC_MinMintConfirmations = 20;
        consensus.ZC_MinMintFee = 1 * CENT;
        consensus.ZC_MinStakeDepth = 200;
        consensus.ZC_TimeStart = 1501776000;
        consensus.ZC_WrappedSerialsSupply = 0;   // WrappedSerials only on main net

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight                  = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight             = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight                   = 1001;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight                = 1441;
        consensus.vUpgrades[Consensus::UPGRADE_ZC].nActivationHeight                    = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_ZC_V2].nActivationHeight                 = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight                 = 1441;
        consensus.vUpgrades[Consensus::UPGRADE_ZC_PUBLIC].nActivationHeight             = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].nActivationHeight                  = 1541;
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].nActivationHeight                  = 1641;
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].nActivationHeight              = 1741;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].nActivationHeight    = 1841;

        consensus.vUpgrades[Consensus::UPGRADE_ZC].hashActivationBlock                  = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_ZC_V2].hashActivationBlock               = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].hashActivationBlock               = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_ZC_PUBLIC].hashActivationBlock           = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].hashActivationBlock                = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].hashActivationBlock                = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].hashActivationBlock            = uint256S("0x0");
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MIN_DEPTH_V2].hashActivationBlock  = uint256S("0x0");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */

        pchMessageStart[0] = 0xb7;
        pchMessageStart[1] = 0x8b;
        pchMessageStart[2] = 0x4c;
        pchMessageStart[3] = 0xd3;
        nDefaultPort = __PORT_TESTNET__;

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        //vSeeds.push_back(CDNSSeedData("xxx", "xxx"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 65); // Testnet ntrnbh addresses start with 'T'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 66);  // Testnet ntrnbh script addresses start with 'T'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 239);     // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
        // Testnet ntrnbh BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet ntrnbh BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        // Testnet ntrnbh BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";

        genesis = CreateGenesisBlock(1656793446, 582448, 0x1e0ffff0, 1, 0 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x80251aff18129581f06b3036bda4d571b909389699290deced973ebb580d11c5"));
        assert(genesis.hashMerkleRoot == uint256S("0x80251aff18129581f06b3036bda4d571b909389699290deced973ebb580d11c5"));

        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.powLimit   = ~UINT256_ZERO >> 20;
        consensus.posLimitV1 = ~UINT256_ZERO >> 24;
        consensus.posLimitV2 = ~UINT256_ZERO >> 20;
        consensus.nBudgetCycleBlocks = 30 * 24 * 60;       // approx. 1 every 30 days
        consensus.nBudgetFeeConfirmations = 6;      // Number of confirmations for the finalization fee
        consensus.nCoinbaseMaturity = 80;
        consensus.nFutureTimeDriftPoW = 7200;
        consensus.nFutureTimeDriftPoS = 180;
        consensus.nMasternodeCountDrift = 20;       // num of MN we allow the see-saw payments to be off by
        consensus.nMaxMoneyOut = 50000000 * COIN;
        consensus.nPoolMaxTransactions = 3;
        consensus.nProposalEstablishmentTime = 60 * 60 * 24;    // must be at least a day old to make it into a budget
        consensus.nStakeMinAge = 5 * 60 * 60; // Neutron - 5 hours
        consensus.nStakeMinDepth = 100;
        consensus.nStakeMinDepthV2 = 600;
        consensus.nTargetTimespan = 20 * 60;  // Neutron - every 20mins
        consensus.nTargetTimespanV2 = 20 * 60;  // Neutron - every 20mins
        consensus.nTargetSpacing = 1 * 79; // Neutron - 79 secs
        consensus.nTimeSlotLength = 15;

        /* Spork Key for RegTest:
        WIF private key:
        private key hex: cRsUdhyMYPrwFj2z3PnhkxcgptPm4PSBj6HJivt8iy4Xwe1Li2gi
        Address: TXxFB5kDGfkuEkA16yBRDo7DdKvFoxdcL6
        */
        consensus.strSporkPubKey = "042b98d4150746cc5ee1b5a991244f8a2b155630efbfa490fee76202912ed2d6e"
                           "9b6e5c62d424b9f5878ee7aff68e9aa84d10821a33e99de27fed2d77f57247954";
        consensus.strSporkPubKeyOld = "042E0E340B40681EEFB7C67B7CBE968E3AB47F4A393E3626E13309CFDC5A1C5D5"
                           "B9537CD3CEBA3B5B1656D2949355CADA0F5EE74C4EDCCBEF84BF80151EF3B0C0A";
        consensus.nTime_EnforceNewSporkKey = 0;
        consensus.nTime_RejectOldSporkKey = 0;

        // height based activations
        consensus.height_last_ZC_AccumCheckpoint = 310;     // no checkpoints on regtest
        consensus.height_last_ZC_WrappedSerials = -1;
        consensus.height_start_InvalidUTXOsCheck = 999999999;
        consensus.height_start_ZC_InvalidSerials = 999999999;
        consensus.height_start_ZC_SerialRangeCheck = 300;
        consensus.height_ZC_RecalcAccumulators = 999999999;

        // Zerocoin-related params
        consensus.ZC_Modulus = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784"
                "4069182906412495150821892985591491761845028084891200728449926873928072877767359714183472702618963750149718246911"
                "6507761337985909570009733045974880842840179742910064245869181719511874612151517265463228221686998754918242243363"
                "7259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133"
                "8441436038339044149526344321901146575444541784240209246165157233507787077498171257724679629263863563732899121548"
                "31438167899885040445364023527381951378636564391212010397122822120720357";
        consensus.ZC_MaxPublicSpendsPerTx = 637;    // Assume about 220 bytes each input
        consensus.ZC_MaxSpendsPerTx = 7;            // Assume about 20kb each input
        consensus.ZC_MinMintConfirmations = 10;
        consensus.ZC_MinMintFee = 1 * CENT;
        consensus.ZC_MinStakeDepth = 10;
        consensus.ZC_TimeStart = 0;                 // not implemented on regtest
        consensus.ZC_WrappedSerialsSupply = 0;

        // Network upgrades
        consensus.vUpgrades[Consensus::BASE_NETWORK].nActivationHeight =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight =
                Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_POS].nActivationHeight           = 251;
        consensus.vUpgrades[Consensus::UPGRADE_POS_V2].nActivationHeight        = 251;
        consensus.vUpgrades[Consensus::UPGRADE_ZC].nActivationHeight            = 300;
        consensus.vUpgrades[Consensus::UPGRADE_ZC_V2].nActivationHeight         = 300;
        consensus.vUpgrades[Consensus::UPGRADE_BIP65].nActivationHeight         =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_ZC_PUBLIC].nActivationHeight     = 400;
        consensus.vUpgrades[Consensus::UPGRADE_STAKE_MODIFIER_V2].nActivationHeight          = 251;
        consensus.vUpgrades[Consensus::UPGRADE_TIME_PROTOCOL_V2].nActivationHeight          =
                Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_P2PKH_BLOCK_SIGNATURES].nActivationHeight       = 300;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */

        pchMessageStart[0] = 0xb8;
        pchMessageStart[1] = 0xc2;
        pchMessageStart[2] = 0x47;
        pchMessageStart[3] = 0x38;
        nDefaultPort = __PORT_REGTEST__;

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_NETWORK && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }
};
static CRegTestParams regTestParams;

static CChainParams* pCurrentParams = 0;

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

/*CScript GetDeveloperScript()
{
    string strAddress;

    // if (sporkManager.IsSporkActive(SPORK_6_UPDATED_DEV_PAYMENTS_ENFORCEMENT)) {
    //     // v2.0.1
    //     strAddress = fTestNet ? DEVELOPER_ADDRESS_TESTNET_V2 : DEVELOPER_ADDRESS_MAINNET_V2;
    // } else {
    //     // v2.0.0
    //     strAddress = fTestNet ? DEVELOPER_ADDRESS_TESTNET_V1 : DEVELOPER_ADDRESS_MAINNET_V1;
    // }

    // if (sporkManager.IsSporkActive(SPORK_10_V3_DEV_PAYMENTS_ENFORCEMENT)) {
    //     // v3.0.0
    //     strAddress = fTestNet ? DEVELOPER_ADDRESS_TESTNET_V3 : DEVELOPER_ADDRESS_MAINNET_V3;
    // } else {
    //     // v2.0.1
    //     strAddress = fTestNet ? DEVELOPER_ADDRESS_TESTNET_V2 : DEVELOPER_ADDRESS_MAINNET_V2;
    // }

    // v3.0.0+ default
    strAddress = fTestNet ? DEVELOPER_ADDRESS_TESTNET_V3 : DEVELOPER_ADDRESS_MAINNET_V3;

    return GetScriptForDestination(CBitcoinAddress(strAddress).Get());
}

int64_t GetDeveloperPayment(int64_t nBlockValue)
{
    // if (sporkManager.IsSporkActive(SPORK_6_UPDATED_DEV_PAYMENTS_ENFORCEMENT)) {
    //     // v2.0.1
    //     return nBlockValue * DEVELOPER_PAYMENT_V2 / COIN;
    // }

    // v2.0.0
    // return nBlockValue * DEVELOPER_PAYMENT_V1 / COIN;

    // v3.0.0+ default
    return nBlockValue * DEVELOPER_PAYMENT_V2 / COIN;
}

int64_t GetMasternodePayment(int nHeight, int64_t blockValue)
{
    int64_t nDeveloperPayment = GetDeveloperPayment(blockValue);
    return (blockValue - nDeveloperPayment) * 66 / 100; // 66%
}*/
