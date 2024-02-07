#include "RsPsi.h"
#include <array>
#include <future>

//#include "thirdparty/parallel-hashmap/parallel_hashmap/phmap.h"
namespace volePSI
{

    template <typename T>
    struct Buffer : public span<T>
    {
        std::unique_ptr<T[]> mPtr;

        void resize(u64 s)
        {
            mPtr.reset(new T[s]);
            static_cast<span<T> &>(*this) = span<T>(mPtr.get(), s);
        }
    };

    void details::RsPsiBase::init(
        u64 senderSize,
        u64 recverSize,
        u64 statSecParam,
        block seed,
        bool malicious,
        u64 numThreads,
        bool useReducedRounds)
    {

        mSenderSize = senderSize;
        mRecverSize = recverSize;
        mSsp = statSecParam;

        mPrng.SetSeed(seed);

        mMalicious = malicious;

        mMaskSize = malicious ? sizeof(block) : std::min<u64>(oc::divCeil(mSsp + oc::log2ceil(mSenderSize * mRecverSize), 8), sizeof(block));
        mCompress = mMaskSize != sizeof(block);

        mNumThreads = numThreads;
        mUseReducedRounds = useReducedRounds;
    }

    Proto RsPsiSender::run(span<block> inputs, Socket &chl)
    {
        for(u64 i;i<inputs.size();i++)
      {
         std::cout << i<<":sender\n"<< inputs[i] << std::endl;
      }
        std::vector<block> buffer;
        buffer.resize(inputs.size() * sizeof(block));
        // std::vector<block> buffer3;
        // buffer3.resize(inputs.size() * sizeof(block));
        MC_BEGIN(Proto, this, inputs, &chl, buffer,
                 hashes = std::move(Buffer<u8>{}));
        // std::cout << "&chl" << &chl << std::endl; // 0x7ffe31431410
        // std::cout << "this" << this << std::endl; // 0x7ffe31431530
        setTimePoint("RsPsiSender::run-begin");

        // std::cout << "mTimer" << mTimer << std::endl;
        if (mTimer) // 0x7ffe31431340
            mSender.setTimer(getTimer());

        // std::cout << "getTimer()++++++++++++++++\n" <<  getTimer() << std::endl;

        mSender.mMalicious = mMalicious;
        MC_AWAIT(mSender.send(mRecverSize, mPrng, chl, mNumThreads, mUseReducedRounds));
        // std::cout << "mRecverSize" << mRecverSize << std::endl;             // n=8 mRecverSize256
        // std::cout << "mNumThreads" << mNumThreads << std::endl;             // 1
        // std::cout << "mUseReducedRounds" << mUseReducedRounds << std::endl; // n=8 0
        setTimePoint("RsPsiSender::run-opprf");
        // std::cout << "inputs.size() * sizeof(block)" << inputs.size() * sizeof(block) << std::endl; // n=8 mSenderSize * mMaskSize 1792
        hashes.resize(inputs.size() * sizeof(block));

        // mSender.eval(inputs, span<block>((block*)hashes.data(), inputs.size()),mNumThreads);
        mSender.eval1(inputs, span<block>((block *)hashes.data(), inputs.size()), buffer, mNumThreads);

        std::cout << "buffer[1]++++++++++++" << buffer[1] << std::endl;
        // MC_AWAIT(chl.send(std::move(buffer)));
        MC_AWAIT(chl.send(buffer));
        
        // chl.send(std::move(test));
        // std::cout << "(block*)hashes.data()" << (block *)hashes.data() << std::endl; //(block*)data.get()0x557205b0eac0
        // std::cout << "inputs.size()" << inputs.size() << std::endl;                  // n=8 256
        // std::cout << "mNumThreads" << mNumThreads << std::endl;                      // n=8 1
        setTimePoint("RsPsiSender::run-eval");
        if (mCompress)
        {
            auto src = (block *)hashes.data();
            auto dest = (u8 *)hashes.data();
            u64 i = 0;

            for (; i < std::min<u64>(mSenderSize, 100); ++i)
            {
                memmove(dest, src, mMaskSize);
                dest += mMaskSize;
                src += 1;
            }
            for (; i < mSenderSize; ++i)
            {
                memcpy(dest, src, mMaskSize);
                dest += mMaskSize;
                src += 1;
            }
            static_cast<span<u8> &>(hashes) = span<u8>((u8 *)hashes.data(), dest);
        }

        MC_AWAIT(chl.send(std::move(hashes))); // hashes
        // std::cout << "buffer[1]" << buffer[1] << std::endl;
        // MC_AWAIT(chl.send(std::move(buffer)));
        setTimePoint("RsPsiSender::run-sendHash");

        MC_END();
    }

    namespace
    {
        struct NoHash
        {
            inline size_t operator()(const block &v) const
            {
                return v.get<size_t>(0);
            }
        };
    }

    Proto RsPsiReceiver::run(span<block> inputs, Socket &chl)
    {
        setTimePoint("RsPsiReceiver::run-enter");
        static const u64 batchSize = 128;

        struct MultiThread
        {
            std::promise<void> prom;
            std::shared_future<void> fu;
            std::vector<std::thread> thrds;
            std::function<void(u64)> routine;
            std::atomic<u64> numDone;
            std::promise<void> hashingDoneProm;
            std::shared_future<void> hashingDoneFu;
            std::mutex mMergeMtx;
            u64 numThreads;
            u64 binSize;
            libdivide::libdivide_u32_t divider;
        };
        std::vector<block> buffer3(8);
        std::vector<block> buffer4(8);
        for(u64 i;i<inputs.size();i++)
        {
           std::cout << i<<":recver\n"<< inputs[i] << std::endl;
        }
        buffer3.resize(inputs.size() * sizeof(block));
        buffer4.resize(inputs.size() * sizeof(block));
        MC_BEGIN(Proto, this, inputs, &chl,
                 buffer3,
                 buffer4,
                 buff = std::vector<block>{},
                 data = std::unique_ptr<u8[]>{}, // unique_ptr for array objects with a runtime length
                 myHashes = span<block>{},
                 theirHashes = oc::MatrixView<u8>{},
                 map = google::dense_hash_map<block, u64, NoHash>{},
                 i = u64{},
                 main = u64{},
                 hh = std::array<std::pair<block, u64>, 128>{},
                 mt = std::unique_ptr<MultiThread>{},
                 mask = block{});
        setTimePoint("RsPsiReceiver::run-begin");

        data = std::unique_ptr<u8[]>(new u8[mSenderSize * mMaskSize +
                                            mRecverSize * sizeof(block)]); // array objects with a runtime length

        // std::cout << "data.get()+++++++++++++++++\n"
        //<< data.get() << std::endl; /// Return the stored pointer.

        // std::cout << " mMaskSize" << mMaskSize << std::endl;
        // std::cout << "mSenderSize * mMaskSize" << mSenderSize * mMaskSize << std::endl;         // n=3   8*6=48  n=4 16*6=96
        // std::cout << "mRecverSize * sizeof(block)" << mRecverSize * sizeof(block) << std::endl; // n=3 8*16=128  n=4 16*16=256

        myHashes = span<block>((block *)data.get(), mRecverSize);
        

        std::cout << "(block*)data.get()" << (block *)data.get() << std::endl;
        std::cout << "mRecverSize" << mRecverSize << std::endl;

        theirHashes = oc::MatrixView<u8>((u8 *)((block *)data.get() + mRecverSize), mSenderSize, mMaskSize);
        

        setTimePoint("RsPsiReceiver::run-alloc");

        if (mTimer)
            mRecver.setTimer(getTimer());

        mRecver.mMalicious = mMalicious;

        // todo, parallelize these two
        std::cout << "mUseReducedRounds" << mUseReducedRounds << std::endl;
        MC_AWAIT(mRecver.receive(inputs, myHashes, mPrng, chl, mNumThreads, mUseReducedRounds)); // The MC_AWAIT macro can then be used to await some awaitable, e.g. task<>
        setTimePoint("RsPsiReceiver::run-oprf");

        mask = oc::ZeroBlock; // 32 ~0
        std::cout << "mask" << mask << std::endl;
        std::cout << "mMaskSize" << mMaskSize << std::endl; // 6
        buff.resize(inputs.size() * sizeof(block));
        MC_AWAIT(chl.recv(buffer3));
        std::cout << "buff[1]--------------------" << buffer3[1] << std::endl;
        for (i = 0; i < mMaskSize; ++i)
        {
            mask.set<u8>(i, ~0);
        }

        if (mNumThreads < 2) // 1
        {

            map.resize(myHashes.size()); // 16
                                         // std::cout << "myHashes.size()" << myHashes.size() << std::endl; // 16
            setTimePoint("RsPsiReceiver::run-reserve");
            map.set_empty_key(oc::ZeroBlock);
            // std::cout << "oc::ZeroBlock" << oc::ZeroBlock << std::endl;
            setTimePoint("RsPsiReceiver::run-set_empty_key");
            // std::cout << "batchSize" << batchSize << std::endl;
            main = mRecverSize / batchSize * batchSize;
            // std::cout << "mRecverSize" << main << std::endl;
            // std::cout << "main" << main << std::endl;
            // std::cout << "mRecverSize / batchSize * batchSize" << mRecverSize / batchSize * batchSize << std::endl;
            // std::cout << "mCompress" << mCompress << std::endl;

            if (!mCompress) // 0
            {
                std::cout << "batchSize" << batchSize << std::endl;
                for (i = 0; i < main; i += batchSize)
                {
                    for (u64 j = 0; j < batchSize; ++j)
                    {

                        hh[j] = {myHashes[i + j], i + j};
                        // std::cout << " i " << i << std::endl;
                        // std::cout << " j " << j << std::endl;
                        // std::cout << " i + j " << i + j << std::endl;
                        // std::cout << "myHashes[i + j]" << myHashes[i + j] << std::endl;
                        // std::cout << "myHashes[6]" << myHashes[6] << std::endl;
                    }
                    map.insert(hh.begin(), hh.end());
                    // std::cout << "hh.begin()" << hh.begin() << std::endl;
                    // std::cout << " hh.end() " << hh.end()  << std::endl;
                }
                for (; i < mRecverSize; ++i)
                {
                    map.insert({myHashes[i], i});
                    // std::cout << "myHashes[i]" << myHashes[i] << std::endl;
                    // std::cout << " i " << i  << std::endl;
                }
            }
            else
            {

                for (i = 0; i < main; i += batchSize)
                {
                    for (u64 j = 0; j < batchSize; ++j)
                    {
                        // std::cout << "i" <<i<<"j"<<j<<"\n"<<myHashes[i+j]<< std::endl;
                        //  std::cout << "mask" << mask << std::endl;
                        hh[j] = {myHashes[i + j] & mask, i + j}; // jiaoyan
                    }
                    // std::cout << "myHashes[6]"<<myHashes[6]<< std::endl;
                    map.insert(hh.begin(), hh.end());
                    // std::cout << "hh.begin()" << hh.begin() << std::endl;
                    // std::cout << "hh.end() " << hh.end()  << std::endl;
                }
                for (; i < mRecverSize; ++i)
                {
                    // std::cout <<"i"<< i << "myHashes[i]" << myHashes[i]  << std::endl;
                    map.insert({myHashes[i] & mask, i});
                }
            }

            setTimePoint("RsPsiReceiver::run-insert");
            // u64 test1;
            // chl.recv(test1);
            // std::cout << "test1" << test1 << std::endl;
            MC_AWAIT(chl.recv(theirHashes));

            setTimePoint("RsPsiReceiver::run-recv");

            block h = oc::ZeroBlock;
           // std::cout << "h" << h << std::endl;
            auto iter = theirHashes.data();

            // std::cout << "iter" << iter << std::endl;
            // std::cout << "mSenderSize" << mSenderSize << std::endl;
            for (i = 0; i < mSenderSize; ++i)
            {
                // std::cout << "mSenderSize" << mSenderSize << std::endl;
                memcpy(&h, iter, mMaskSize);
                // std::cout << "&h" << &h << std::endl;
                // std::cout << "iter" << iter << std::endl;
                // std::cout << "mMaskSize" << mMaskSize << std::endl;
                iter += mMaskSize;
                //std::cout << "iter" << iter << std::endl;
                //  std::cout << "h" << h << std::endl;
                auto iter = map.find(h);

                if (iter != map.end())
                {

                    mIntersection.push_back(iter->second);
                }
            }
            u64 size=mIntersection.size();
            std::cout << "size" << size << std::endl;
            for (i = 0; i < size; ++i)
          {
               std::cout << "mIntersection[i]" << mIntersection[i] << std::endl;
          }
           
            setTimePoint("RsPsiReceiver::Dec");
            //std::cout << "myHashes.front()" << myHashes.front() << std::endl;
            //std::cout << "myHashes[0]" << myHashes[0] << std::endl;
            for(i=0;i<size;i++)
            {
            oc::AESDec De(myHashes[i]);
            De.ecbDecBlock(buffer3[i], buffer4[i]);
            std::cout << "mingwen" << inputs[i] << std::endl;
            std::cout << "miwen" << buffer3[i] << std::endl;
            std::cout << "mingwen" << buffer4[i] << std::endl;
            }
             setTimePoint("RsPsiReceiver::run-find");
             setTimePoint("RsPsiReceiver::successful");
        }
        else
        {
            mt.reset(new MultiThread);

            mt->fu = mt->prom.get_future().share();

            setTimePoint("RsPsiReceiver::run-reserve");

            mt->numDone = 0;
            mt->hashingDoneFu = mt->hashingDoneProm.get_future().share();
            std::cout << "mNumThreads" << mNumThreads << std::endl;
            mt->numThreads = std::max<u64>(1, mNumThreads);
            std::cout << " mt->numThreads" << mt->numThreads << std::endl;

            mt->binSize = Baxos::getBinSize(mNumThreads, mRecverSize, mSsp);
            std::cout << "mt->binSize" << mt->binSize << std::endl;

            mt->divider = libdivide::libdivide_u32_gen(mt->numThreads);

            mt->routine = [&](u64 thrdIdx)
            {
                if (!thrdIdx)
                    setTimePoint("RsPsiReceiver::run-threadBegin");

                auto &divider = mt->divider;
                google::dense_hash_map<block, u64, NoHash> map(mt->binSize);
                map.set_empty_key(oc::ZeroBlock);

                if (!thrdIdx)
                    setTimePoint("RsPsiReceiver::run-set_empty_key_par");

                u64 i = 0;
                std::array<std::pair<block, u64>, batchSize> hh;
                for (; i < myHashes.size();)
                {
                    u64 j = 0;
                    while (j != batchSize && i < myHashes.size())
                    {
                        auto v = myHashes[i].get<u32>(0);
                        auto k = libdivide::libdivide_u32_do(v, &divider);
                        v -= k * mNumThreads;
                        if (v == thrdIdx)
                        {
                            hh[j] = {myHashes[i] & mask, i};
                            ++j;
                        }
                        ++i;
                    }
                    map.insert(hh.begin(), hh.begin() + j);
                }

                if (++mt->numDone == mt->numThreads)
                    mt->hashingDoneProm.set_value();
                else
                    mt->hashingDoneFu.get();

                if (!thrdIdx)
                    setTimePoint("RsPsiReceiver::run-insert_par");

                mt->fu.get();
                if (!thrdIdx)
                    setTimePoint("RsPsiReceiver::run-recv_par");

                auto begin = thrdIdx * myHashes.size() / mNumThreads;
                u64 intersectionSize = 0;
                u64 *intersection = (u64 *)&myHashes[begin];

                {
                    block h = oc::ZeroBlock;
                    auto iter = theirHashes.data();
                    for (i = 0; i < mSenderSize; ++i)
                    {
                        memcpy(&h, iter, mMaskSize);
                        iter += mMaskSize;

                        auto v = h.get<u32>(0);
                        auto k = libdivide::libdivide_u32_do(v, &divider);
                        v -= k * mNumThreads;
                        if (v == thrdIdx)
                        {
                            auto iter = map.find(h);
                            if (iter != map.end())
                            {
                                intersection[intersectionSize] = iter->second;
                                ++intersectionSize;
                            }
                        }
                    }
                }

                if (!thrdIdx)
                    setTimePoint("RsPsiReceiver::run-find_par");
                if (intersectionSize)
                {
                    std::lock_guard<std::mutex> lock(mt->mMergeMtx);
                    mIntersection.insert(mIntersection.end(), intersection, intersection + intersectionSize);
                }
            };

            mt->thrds.resize(mt->numThreads);
            for (i = 0; i < mt->thrds.size(); ++i)
                mt->thrds[i] = std::thread(mt->routine, i);
            MC_AWAIT(chl.recv(theirHashes));
            mt->prom.set_value();

            for (i = 0; i < mt->thrds.size(); ++i)
                mt->thrds[i].join();

            setTimePoint("RsPsiReceiver::run-done");
        }

        MC_END();
    }

}