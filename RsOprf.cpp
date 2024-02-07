#include "RsOprf.h"
using namespace std;
namespace volePSI
{
    Proto RsOprfSender::send(u64 n, PRNG &prng, Socket &chl, u64 numThreads, bool reducedRounds)
    {
        MC_BEGIN(Proto, this, n, &prng, &chl, numThreads, reducedRounds,
                 ws = block{},
                 hBuff = std::array<u8, 32>{},
                 ro = oc::RandomOracle(32),
                 pPtr = std::unique_ptr<block[]>{},
                 pp = span<block>{},
                 subPp = span<block>{},
                 remB = span<block>{},
                 subB = span<block>{},
                 fu = std::move(macoro::eager_task<void>{}),
                 tIter = (block*)nullptr,
                 recvIdx = u64{0},
                 fork = Socket{});
        //std::cout << "numThreads" << numThreads << std::endl;       // 1
        //std::cout << "reducedRounds" << reducedRounds << std::endl; // 0

        setTimePoint("RsOprfSender::send-begin");
        ws = prng.get();
       // std::cout << "ws" << ws << std::endl;
        mPaxos.init(n, mBinSize, 3, 40, PaxosParam::GF128, oc::ZeroBlock);
        mD = prng.get();
       // std::cout << "mD" << mD << std::endl;
       // std::cout << "mMalicious" << mMalicious << std::endl;
        if (mMalicious) // 0
        {
            mVoleSender.mMalType = oc::SilentSecType::Malicious;
            ro.Update(ws);
            ro.Final(hBuff);
            MC_AWAIT(chl.send(std::move(hBuff)));
        }
        // std::cout<<"mTimer+++++++++"<<mTimer<<std::endl;
        if (mTimer)
            mVoleSender.setTimer(*mTimer);
       // std::cout << "mTimer+++++++++" << *mTimer << std::endl;
        numThreads = std::max<u64>(1, numThreads);
        mVoleSender.mNumThreads = numThreads;
        //std::cout << "numThreads" << numThreads << std::endl;
        // a + b  = c * d
        fork = chl.fork();                                              // socket
        fu = genVole(prng, fork, reducedRounds) | macoro::make_eager(); // SilentVoleSender.ot.enter   SilentVoleSender.genSilent.begin

        MC_AWAIT(chl.recv(mPaxos.mSeed)); // socket
        setTimePoint("RsOprfSender::recv-seed");
        MC_AWAIT(fu);
        mB = mVoleSender.mB;//b

        setTimePoint("RsOprfSender::send-vole");

        if (mMalicious)
        {
            MC_AWAIT(chl.recv(mW));
            MC_AWAIT(chl.send(std::move(ws)));
            mW = mW ^ ws;
            setTimePoint("RsOprfSender::recv-mal");
        }
       // std::cout << "mPaxos.size()" << mPaxos.size() << std::endl;
        //std::cout << "new block[mPaxos.size()]" << new block[mPaxos.size()] << std::endl;
        pPtr.reset(new block[mPaxos.size()]); // Replace the stored pointer.
        //std::cout << "new block[mPaxos.size()]" << pPtr.get() << std::endl;
        pp = span<block>(pPtr.get(), mPaxos.size());

        setTimePoint("RsOprfSender::alloc ");

        if (0)
        {
            MC_AWAIT(chl.recv(pp));

            setTimePoint("RsOprfSender::send-recv");
            {

                auto main = mB.size() / 8 * 8;
                auto b = mB.data();
                auto p = pp.data();
                for (u64 i = 0; i < main; i += 8)
                {
                    b[0] = b[0] ^ mD.gf128Mul(p[0]);
                    b[1] = b[1] ^ mD.gf128Mul(p[1]);
                    b[2] = b[2] ^ mD.gf128Mul(p[2]);
                    b[3] = b[3] ^ mD.gf128Mul(p[3]);
                    b[4] = b[4] ^ mD.gf128Mul(p[4]);
                    b[5] = b[5] ^ mD.gf128Mul(p[5]);
                    b[6] = b[6] ^ mD.gf128Mul(p[6]);
                    b[7] = b[7] ^ mD.gf128Mul(p[7]);

                    b += 8;
                    p += 8;
                }

                for (u64 i = main; i < mB.size(); ++i)
                {
                    mB[i] = mB[i] ^ mD.gf128Mul(pp[i]);
                }
            }
            setTimePoint("RsOprfSender::send-gf128Mul");
        }
        else
        {
            remB = mB;
            std::cout << "pp.size()" << pp.size() << std::endl;
            while (pp.size())
            {

                subPp = pp.subspan(0, std::min<u64>(pp.size(), 1 << 28));
                pp = pp.subspan(subPp.size());

                subB = remB.subspan(0, subPp.size());
                remB = remB.subspan(subPp.size());

                setTimePoint("RsOprfSender::pre*-" + std::to_string(recvIdx));
                MC_AWAIT(chl.recv(subPp));
                setTimePoint("RsOprfSender::recv-" + std::to_string(recvIdx));

                {

                    auto main = subB.size() / 8 * 8;
                    //std::cout << "main " << main << std::endl;
                    auto b = subB.data();
                    //std::cout << "b " << b << std::endl;
                    auto p = subPp.data();
                    //std::cout << "p " << p << std::endl;
                    for (u64 i = 0; i < main; i += 8)
                    {

                        b[0] = b[0] ^ mD.gf128Mul(p[0]);
                        
                        b[1] = b[1] ^ mD.gf128Mul(p[1]);
                       
                        b[2] = b[2] ^ mD.gf128Mul(p[2]);
                        
                        b[3] = b[3] ^ mD.gf128Mul(p[3]);
                        
                        b[4] = b[4] ^ mD.gf128Mul(p[4]);
                        
                        b[5] = b[5] ^ mD.gf128Mul(p[5]);
                        
                        b[6] = b[6] ^ mD.gf128Mul(p[6]);
                       
                        b[7] = b[7] ^ mD.gf128Mul(p[7]);
                        
                        b += 8;
                        p += 8;
                    }
                   // std::cout << "subB.size()" << subB.size() << std::endl;
                    for (u64 i = main; i < subB.size(); ++i, ++b, ++p)
                    {
                        *b = *b ^ mD.gf128Mul(*p);
                        std::cout << "*b" << *b << std::endl;
                        std::cout << "b" << b << std::endl;
                        std::cout << "p" << p << std::endl;
                    }
                }
                setTimePoint("RsOprfSender::gf128Mul-" + std::to_string(recvIdx));

                ++recvIdx;
            }
        }

        MC_END();
    }

    block RsOprfSender::eval(block v)
    {
        block o;
        eval({&v, 1}, {&o, 1}, 1);
        return o;
    }
    void RsOprfSender::eval1(span<const block> val, span<block> output,vector<block>& buffer,u64 numThreads)
    {

       
        setTimePoint("RsOprfSender::eval-begin");

        mPaxos.decode<block>(val, output, mB, numThreads);//output=Decode(K; y; r  )

        setTimePoint("RsOprfSender::eval-decode");

        auto main = val.size() / 8 * 8;
        //std::cout << "main" << main << std::endl;
        auto o = output.data();
        //std::cout << "o" << o << std::endl;
        auto v = val.data();
        //std::cout << "v" << v << std::endl;
        std::array<block, 8> h;
        std::array<block, 8> h_1;
        auto cp = span<block>{};

      
        // todo, parallelize this.
        if (mMalicious)
        {
            oc::MultiKeyAES<8> hasher;

            // main = 0;
            for (u64 i = 0; i < main; i += 8)
            {
                oc::mAesFixedKey.hashBlocks<8>(v, h.data());
                o[0] = o[0] ^ mD.gf128Mul(h[0]);
                o[1] = o[1] ^ mD.gf128Mul(h[1]);
                o[2] = o[2] ^ mD.gf128Mul(h[2]);
                o[3] = o[3] ^ mD.gf128Mul(h[3]);
                o[4] = o[4] ^ mD.gf128Mul(h[4]);
                o[5] = o[5] ^ mD.gf128Mul(h[5]);
                o[6] = o[6] ^ mD.gf128Mul(h[6]);
                o[7] = o[7] ^ mD.gf128Mul(h[7]);

                o[0] = o[0] ^ mW;
                o[1] = o[1] ^ mW;
                o[2] = o[2] ^ mW;
                o[3] = o[3] ^ mW;
                o[4] = o[4] ^ mW;
                o[5] = o[5] ^ mW;
                o[6] = o[6] ^ mW;
                o[7] = o[7] ^ mW;

                hasher.setKeys({o, 8});
                hasher.hashNBlocks(v, o);

                o += 8;
                v += 8;
            }
            for (u64 i = main; i < val.size(); ++i)
            {
                auto h = oc::mAesFixedKey.hashBlock(val[i]);
                output[i] = output[i] ^ mD.gf128Mul(h);

                output[i] = output[i] ^ mW;
                output[i] = oc::AES(output[i]).hashBlock(val[i]);
            }
        }
        else
        {

            for (u64 i = 0; i < main; i += 8)
            {
                oc::mAesFixedKey.hashBlocks<8>(v, h.data());
                // auto h = v;

                o[0] = o[0] ^ mD.gf128Mul(h[0]);
               
                o[1] = o[1] ^ mD.gf128Mul(h[1]);
              
                o[2] = o[2] ^ mD.gf128Mul(h[2]);
                
                o[3] = o[3] ^ mD.gf128Mul(h[3]);
               
                o[4] = o[4] ^ mD.gf128Mul(h[4]);
                
                o[5] = o[5] ^ mD.gf128Mul(h[5]);
                
                o[6] = o[6] ^ mD.gf128Mul(h[6]);
              
                o[7] = o[7] ^ mD.gf128Mul(h[7]);
               

                oc::mAesFixedKey.hashBlocks<8>(o, o);

                o += 8;
                v += 8;
            }

            for (u64 i = main; i < val.size(); ++i)
            {
                auto h = oc::mAesFixedKey.hashBlock(val[i]);
                
                output[i] = output[i] ^ mD.gf128Mul(h);
              
                output[i] = oc::mAesFixedKey.hashBlock(output[i]);
                
               
               
            }
        }
            setTimePoint("RsOprfSender::enc");
            u64 m;
            //vector<block> buffer2;
            vector<block> buffer1;
            buffer1.resize(val.size() * sizeof(block));
            buffer.resize(val.size() * sizeof(block));
           // std::vector<block> buffer1(oc::divCeil(m, sizeof(block)));
            auto buffPtr = (u8*)buffer.data();
            //std::cout << "buffPtr" << buffPtr << std::endl;
            std::cout << "miyao-------------------output[1]" << output[1] << std::endl; 
            for (u64 i = 0; i < val.size(); ++i)
            {
               
                oc::AES enc(output[i]);
				enc.ecbEncBlock(val[i], buffer[i]);
                //std::cout <<i<<":sender\n"<< v[i] << std::endl; 
                if(i==1){
                     std::cout << "mingwen-------------------val[1]" << val[i] << std::endl; 
                     std::cout << "miwen----------------------buffer2[i]" << buffer[i] << std::endl; 
                }
               
            }
            for (u64 i = 0; i < val.size(); ++i)
            {

               // std::cout << i <<":\n"<<output[i] << std::endl; 
                oc::AESDec De(output[i]);
                //std::cout << "buffer1[1]" << buffer1[i] << std::endl; 
				De.ecbDecBlock(buffer[i],buffer1[i]);
              if(i==1){
                     std::cout << "mingwen----------------------buffer1[1]" << buffer1[i] << std::endl; 
                }
            }


           
       
        setTimePoint("RsOprfSender::eval-hash");
        
    }

    Proto RsOprfSender::genVole(PRNG &prng, Socket &chl, bool reduceRounds)
    {
        std::cout << "reduceRounds" << reduceRounds << std::endl; // 0
        if (reduceRounds)
        {
            MC_BEGIN(Proto, this, &prng, &chl);
            mVoleSender.configure(mPaxos.size(), oc::SilentBaseType::Base);
            MC_AWAIT(mVoleSender.genSilentBaseOts(prng, chl));                     // SilentVoleSender.genSilent.begin
            MC_AWAIT(mVoleSender.silentSendInplace(mD, mPaxos.size(), prng, chl)); // SilentVoleSender.ot.enter
            MC_END();
        }
        else
        {
            return mVoleSender.silentSendInplace(mD, mPaxos.size(), prng, chl);
            std::cout << "mD" << mD << std::endl;
            std::cout << "mPaxos.size()" << mPaxos.size() << std::endl;
        }
    }

    struct UninitVec : span<block>
    {
        std::unique_ptr<block[]> ptr;

        void resize(u64 s)
        {
            ptr.reset(new block[s]);
            static_cast<span<block> &>(*this) = span<block>(ptr.get(), s);
        }
    };

    Proto RsOprfReceiver::receive(span<const block> values, span<block> outputs, PRNG &prng, Socket &chl, u64 numThreads, bool reducedRounds)
    {

        MC_BEGIN(Proto, this, values, outputs, &prng, &chl, numThreads, reducedRounds,
                 hashingSeed = block{},
                 wr = block{},
                 ws = block{},
                 Hws = std::array<u8, 32>{},
                 paxos = Baxos{},
                 hPtr = std::unique_ptr<block[]>{},
                 h = span<block>{},
                 p = std::move(UninitVec{}),
                 subP = span<block>{},
                 subC = span<block>{},
                 a = span<block>{},
                 c = span<block>{},
                 fu = std::move(macoro::eager_task<void>{}),
                 ii = u64{},
                 fork = Socket{});

        setTimePoint("RsOprfReceiver::receive-begin");

        std::cout << "values.size()" << values.size() << "outputs.size()" << outputs.size() << std::endl;
        if (values.size() != outputs.size()) // 0
            throw RTE_LOC;

        hashingSeed = prng.get(), wr = prng.get();
        std::cout << "hashingSeed" << hashingSeed << "wr " << wr << std::endl;
        paxos.init(values.size(), mBinSize, 3, 40, PaxosParam::GF128, hashingSeed);
        std::cout << "std::move(hashingSeed)" << std::move(hashingSeed) << std::endl;
        MC_AWAIT(chl.send(std::move(hashingSeed)));

        if (mMalicious) // 0
        {
            mVoleRecver.mMalType = oc::SilentSecType::Malicious;
            MC_AWAIT(chl.recv(Hws));
        }

        if (mTimer)
            mVoleRecver.setTimer(*mTimer);

        fork = chl.fork();
        fu = genVole(paxos.size(), prng, fork, reducedRounds) | macoro::make_eager();
        std::cout << "paxos.size()" << paxos.size() << std::endl;

        hPtr.reset(new block[values.size()]);//n=8 16
        std::cout << "values.size()" << values.size() << std::endl;

        h = span<block>(hPtr.get(), values.size()); // miwen
        std::cout << "hPtr.get()" << hPtr.get() << std::endl;//0x562d1fb5e150
        std::cout << "values.size()" << values.size() << std::endl;
        oc::mAesFixedKey.hashBlocks(values, h); // An AES instance with a fixed and public key.// Correlation robust hash function.// H(x) = AES(x) + x.

        setTimePoint("RsOprfReceiver::receive-hash");

        // auto pPtr = std::make_shared<std::vector<block>>(paxos.size());
        // span<block> p = *pPtr;

        p.resize(paxos.size());

        setTimePoint("RsOprfReceiver::receive-alloc");

        paxos.solve<block>(values, h, p, nullptr, numThreads);//p
        setTimePoint("RsOprfReceiver::receive-solve");
        MC_AWAIT(fu);

        // a + b  = c * d
        a = mVoleRecver.mA;//C
        c = mVoleRecver.mC;//A'

        setTimePoint("RsOprfReceiver::receive-vole");

        if (mMalicious)
        {
            MC_AWAIT(chl.send(std::move(wr)));
        }

        // if (numThreads > 1)
        //     thrd.join();
        if (0)
        {
            {
                auto main = (p.size() / 8) * 8;
                block *__restrict pp = p.data();
                block *__restrict cc = c.data();
                for (u64 i = 0; i < main; i += 8)
                {
                    pp[0] = pp[0] ^ cc[0];
                    pp[1] = pp[1] ^ cc[1];
                    pp[2] = pp[2] ^ cc[2];
                    pp[3] = pp[3] ^ cc[3];
                    pp[4] = pp[4] ^ cc[4];
                    pp[5] = pp[5] ^ cc[5];
                    pp[6] = pp[6] ^ cc[6];
                    pp[7] = pp[7] ^ cc[7];

                    pp += 8;
                    cc += 8;
                }
                for (u64 i = main; i < p.size(); ++i)
                    p[i] = p[i] ^ c[i];
            }

            setTimePoint("RsOprfReceiver::receive-xor");

            // send c ^ p
            MC_AWAIT(chl.send(std::move(p)));
        }
        else
        {
            ii = 0;
             std::cout << "c.size()" << c.size() << std::endl;
            while (c.size())
            {

                subP = p.subspan(0, std::min<u64>(p.size(), 1 << 28));
                subC = c.subspan(0, subP.size());

                if (p.size() != subP.size())
                    static_cast<span<block> &>(p) = p.subspan(subP.size());
                c = c.subspan(subP.size());

                {

                    auto main = (subP.size() / 8) * 8;
                    block *__restrict pp = subP.data();
                    block *__restrict cc = subC.data();
                    for (u64 i = 0; i < main; i += 8)
                    {
                        pp[0] = pp[0] ^ cc[0];
                        pp[1] = pp[1] ^ cc[1];
                        pp[2] = pp[2] ^ cc[2];
                        pp[3] = pp[3] ^ cc[3];
                        pp[4] = pp[4] ^ cc[4];
                        pp[5] = pp[5] ^ cc[5];
                        pp[6] = pp[6] ^ cc[6];
                        pp[7] = pp[7] ^ cc[7];

                        pp += 8;
                        cc += 8;
                    }
                    for (u64 i = main; i < p.size(); ++i, ++pp, ++cc)
                        *pp = *pp ^ *cc;
                }

                setTimePoint("RsOprfReceiver::receive-xor");

                if (p.size() != subP.size())
                    MC_AWAIT(chl.send(std::move(subP)));
                else
                    MC_AWAIT(chl.send(std::move(p)));

                setTimePoint("RsOprfReceiver::receive-send");

                ++ii;
            }
        }

        paxos.decode<block>(values, outputs, a, numThreads);//Decode(C,x)

        setTimePoint("RsOprfReceiver::receive-decode");

        if (mMalicious)
        {
            MC_AWAIT(chl.recv(ws));

            {
                std::array<u8, 32> Hws2;
                oc::RandomOracle ro(32);
                ro.Update(ws);
                ro.Final(Hws2);
                if (Hws != Hws2)
                    throw RTE_LOC;

                auto w = ws ^ wr;

                // todo, parallelize this.

                // compute davies-meyer F
                //    F(x) = H( Decode(x, a) + w, x)
                // where
                //    H(u,v) = AES_u(v) ^ v

                oc::MultiKeyAES<8> hasher;
                auto main = outputs.size() / 8 * 8;
                auto o = outputs.data();
                auto v = values.data();
                for (u64 i = 0; i < main; i += 8)
                {
                    o[0] = o[0] ^ w;
                    o[1] = o[1] ^ w;
                    o[2] = o[2] ^ w;
                    o[3] = o[3] ^ w;
                    o[4] = o[4] ^ w;
                    o[5] = o[5] ^ w;
                    o[6] = o[6] ^ w;
                    o[7] = o[7] ^ w;

                    // o = H(o, v)
                    hasher.setKeys({o, 8});
                    hasher.hashNBlocks(v, o);

                    o += 8;
                    v += 8;
                }

                for (u64 i = main; i < outputs.size(); ++i)
                {
                    outputs[i] = outputs[i] ^ w;
                    outputs[i] = oc::AES(outputs[i]).hashBlock(values[i]);//X' := fH(Decode(C,x) + w, x) 
                    
                    
                }
            }
        }
        else
        {
            // todo, parallelize this.

            // compute davies-meyer-Oseas F
            //      F(x) = H(Decode(x, a))
            // where
            //      H(u) = AES_fixed(u) ^ u
            oc::mAesFixedKey.hashBlocks(outputs, outputs);  //
             
           
           //oc::MultiKeyAES(outputs);
        }
        setTimePoint("RsOprfReceiver::receive-hash");
        MC_END();
    }

    Proto RsOprfReceiver::genVole(u64 n, PRNG &prng, Socket &chl, bool reducedRounds)
    {
        if (reducedRounds)
        {
            MC_BEGIN(Proto, this, n, &prng, &chl);
            mVoleRecver.configure(n, oc::SilentBaseType::Base);
            MC_AWAIT(mVoleRecver.genSilentBaseOts(prng, chl)); // SilentVoleReceiver.genSilent.begin
            MC_AWAIT(mVoleRecver.silentReceiveInplace(n, prng, chl));
            MC_END();
        }
        else
        {
            return mVoleRecver.silentReceiveInplace(n, prng, chl);
        }
    }
     void RsOprfSender::eval(span<const block> val, span<block> output,u64 numThreads)
    {

       
        setTimePoint("RsOprfSender::eval-begin");

        mPaxos.decode<block>(val, output, mB, numThreads);//output=Decode(K; y; r  )

        setTimePoint("RsOprfSender::eval-decode");

        auto main = val.size() / 8 * 8;
        std::cout << "main" << main << std::endl;
        auto o = output.data();
        std::cout << "o" << o << std::endl;
        auto v = val.data();
        std::cout << "v" << v << std::endl;
        std::array<block, 8> h;
        std::array<block, 8> h_1;
        auto cp = span<block>{};

      
        // todo, parallelize this.
        if (mMalicious)
        {
            oc::MultiKeyAES<8> hasher;

            // main = 0;
            for (u64 i = 0; i < main; i += 8)
            {
                oc::mAesFixedKey.hashBlocks<8>(v, h.data());
                o[0] = o[0] ^ mD.gf128Mul(h[0]);
                o[1] = o[1] ^ mD.gf128Mul(h[1]);
                o[2] = o[2] ^ mD.gf128Mul(h[2]);
                o[3] = o[3] ^ mD.gf128Mul(h[3]);
                o[4] = o[4] ^ mD.gf128Mul(h[4]);
                o[5] = o[5] ^ mD.gf128Mul(h[5]);
                o[6] = o[6] ^ mD.gf128Mul(h[6]);
                o[7] = o[7] ^ mD.gf128Mul(h[7]);

                o[0] = o[0] ^ mW;
                o[1] = o[1] ^ mW;
                o[2] = o[2] ^ mW;
                o[3] = o[3] ^ mW;
                o[4] = o[4] ^ mW;
                o[5] = o[5] ^ mW;
                o[6] = o[6] ^ mW;
                o[7] = o[7] ^ mW;

                hasher.setKeys({o, 8});
                hasher.hashNBlocks(v, o);

                o += 8;
                v += 8;
            }
            for (u64 i = main; i < val.size(); ++i)
            {
                auto h = oc::mAesFixedKey.hashBlock(val[i]);
                output[i] = output[i] ^ mD.gf128Mul(h);

                output[i] = output[i] ^ mW;
                output[i] = oc::AES(output[i]).hashBlock(val[i]);
            }
        }
        else
        {

            for (u64 i = 0; i < main; i += 8)
            {
                oc::mAesFixedKey.hashBlocks<8>(v, h.data());
                // auto h = v;

                o[0] = o[0] ^ mD.gf128Mul(h[0]);
               
                o[1] = o[1] ^ mD.gf128Mul(h[1]);
              
                o[2] = o[2] ^ mD.gf128Mul(h[2]);
                
                o[3] = o[3] ^ mD.gf128Mul(h[3]);
               
                o[4] = o[4] ^ mD.gf128Mul(h[4]);
                
                o[5] = o[5] ^ mD.gf128Mul(h[5]);
                
                o[6] = o[6] ^ mD.gf128Mul(h[6]);
              
                o[7] = o[7] ^ mD.gf128Mul(h[7]);
               

                oc::mAesFixedKey.hashBlocks<8>(o, o);

                o += 8;
                v += 8;
            }

            for (u64 i = main; i < val.size(); ++i)
            {
                auto h = oc::mAesFixedKey.hashBlock(val[i]);
                
                output[i] = output[i] ^ mD.gf128Mul(h);
              
                output[i] = oc::mAesFixedKey.hashBlock(output[i]);
                
               
               
            }
        }
        setTimePoint("RsOprfSender::eval-hash");
        
    }

}