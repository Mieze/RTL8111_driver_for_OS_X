//
//  RealtekRxPool.cpp
//  RealtekRTL8111
//
//  Created by Laura Müller on 26.11.25.
//  Copyright © 2025 Laura Müller. All rights reserved.
//

#include "RealtekRxPool.hpp"

OSDefineMetaClassAndStructors(RealtekRxPool, OSObject);

#define super OSObject

bool RealtekRxPool::init()
{
    return true;
}

void RealtekRxPool::free()
{
    if (refillCE) {
        thread_call_cancel(refillCE);
        IOSleep(1);
        thread_call_free(refillCE);
        refillCE = NULL;
    }
    if (cPktHead) {
        mbuf_freem_list(cPktHead);
        cPktHead = cPktTail = NULL;
        cPktNum = 0;
    }
    if (mPktHead) {
        mbuf_freem_list(mPktHead);
        mPktHead = mPktTail = NULL;
        mPktNum = 0;
    }
    super::free();
}

bool RealtekRxPool::initWithCapacity(UInt32 mbufCapacity,
                                     UInt32 clustCapacity)
{
    mbuf_t m;
    void *data;
    UInt32 i;
    errno_t err;
    unsigned int chunks;
    bool result = false;
    
    if ((mbufCapacity > 0) && (clustCapacity > 0)) {
        cPktHead = cPktTail = NULL;
        mPktHead = mPktTail = NULL;
        cCapacity = clustCapacity;
        cRefillTresh = cCapacity - (cCapacity >> 1);
        mCapacity = mbufCapacity;
        mRefillTresh = mCapacity - (mCapacity >> 1);
        cPktNum = 0;
        mPktNum = 0;
        maxCopySize = mbuf_get_mhlen();
        refillScheduled = false;

        nanoseconds_to_absolutetime(kRefillDelayTime, &refillDelay);

        refillCE = thread_call_allocate_with_options((thread_call_func_t) &refillThread, (void *) this, THREAD_CALL_PRIORITY_KERNEL, 0);

        if (!refillCE) {
            goto done;
        }
        for (i = 0; i < mbufCapacity; i++) {
            chunks = 1;
            err = mbuf_allocpacket(MBUF_WAITOK, maxCopySize, &chunks, &m);

            if (err)
                goto fail_mbuf;

            if (mPktHead) {
                mbuf_setnextpkt(mPktTail, m);
                mPktTail = m;
                mPktNum++;
            } else {
                mPktHead = mPktTail = m;
                mPktNum = 1;
            }
            data = mbuf_datastart(m);
            mbuf_setdata(m, data, 0);
        }
        for (i = 0; i < clustCapacity; i++) {
            chunks = 1;
            err = mbuf_allocpacket(MBUF_WAITOK, PAGE_SIZE, &chunks, &m);

            if (err)
                goto fail_cluster;

            if (cPktHead) {
                mbuf_setnextpkt(cPktTail, m);
                cPktTail = m;
                cPktNum++;
            } else {
                cPktHead = cPktTail = m;
                cPktNum = 1;
            }
            data = mbuf_datastart(m);
            mbuf_setdata(m, data, 0);
        }
        result = true;
    }
done:
    return result;
    
fail_cluster:
    if (cPktHead) {
        mbuf_freem_list(cPktHead);
        cPktHead = cPktTail = NULL;
        cPktNum = 0;
    }

fail_mbuf:
    if (mPktHead) {
        mbuf_freem_list(mPktHead);
        mPktHead = mPktTail = NULL;
        mPktNum = 0;
    }
    goto done;
}

RealtekRxPool *
RealtekRxPool::withCapacity(UInt32 mbufCapacity,
                              UInt32 clustCapacity)
{
    RealtekRxPool *pool = new RealtekRxPool;
    
    if (pool && !pool->initWithCapacity(mbufCapacity,
                                        clustCapacity)) {
        pool->release();
        pool = NULL;
    }
    return pool;
}

mbuf_t RealtekRxPool::getPacket(UInt32 size)
{
    mbuf_t m = NULL;
    void * data;
    errno_t err;
    unsigned int chunks = 1;

    if (size > maxCopySize) {
        err = mbuf_allocpacket(MBUF_DONTWAIT, PAGE_SIZE, &chunks, &m);
        
        if (!err) {
            data = mbuf_datastart(m);
            mbuf_setdata(m, data, 0);
            
        } else if (cPktNum > 1) {
            OSDecrementAtomic(&cPktNum);
            
            m = cPktHead;
            cPktHead = mbuf_nextpkt(cPktHead);
            mbuf_setnextpkt(m, NULL);
            
            if ((cPktNum < cRefillTresh) && !refillScheduled) {
                refillScheduled = true;
                thread_call_enter_delayed(refillCE, refillDelay);
            }
        }
    } else {
        err = mbuf_allocpacket(MBUF_DONTWAIT, maxCopySize, &chunks, &m);

        if (!err) {
            data = mbuf_datastart(m);
            mbuf_setdata(m, data, 0);
            
        } else if (mPktNum > 1) {
            OSDecrementAtomic(&mPktNum);
            
            m = mPktHead;
            mPktHead = mbuf_nextpkt(mPktHead);
            mbuf_setnextpkt(m, NULL);
            
            if ((mPktNum < mRefillTresh) && !refillScheduled) {
                refillScheduled = true;
                thread_call_enter_delayed(refillCE, refillDelay);
            }
        }
    }
    return m;
}

void RealtekRxPool::refillPool()
{
    mbuf_t m;
    void * data;
    errno_t err;
    unsigned int chunks;
    
    while (mPktNum < mCapacity) {
        chunks = 1;
        err = mbuf_allocpacket(MBUF_DONTWAIT, maxCopySize, &chunks, &m);

        if (!err) {
            data = mbuf_datastart(m);
            mbuf_setdata(m, data, 0);
            
            mbuf_setnextpkt(mPktTail, m);
            mPktTail = m;
            OSIncrementAtomic(&mPktNum);
        } else {
            goto done;
        }
    }
    while (cPktNum < cCapacity) {
        chunks = 1;
        err = mbuf_allocpacket(MBUF_DONTWAIT, PAGE_SIZE, &chunks, &m);
        
        if (!err) {
            data = mbuf_datastart(m);
            mbuf_setdata(m, data, 0);

            mbuf_setnextpkt(cPktTail, m);
            cPktTail = m;
            OSIncrementAtomic(&cPktNum);
        } else {
            goto done;
        }
    }

done:
    refillScheduled = false;
}

void RealtekRxPool::refillThread(thread_call_param_t param0)
{
    ((RealtekRxPool *) param0)->refillPool();
}

/*
 * This is an exact copy of IONetworkController's method
 * replaceOrCopyPacket(), except that it tries to get new
 * packets form one of our pool.
 */
mbuf_t RealtekRxPool::replaceOrCopyPacket(mbuf_t *mp,
                                            UInt32 len,
                                            bool * replaced)
{
    mbuf_t m = NULL;
    
    if ((mp != NULL) && (replaced != NULL)) {
        /*
         * Packet needs to be replaced. Try to alloc one
         * get or get one from the cluster buffer pool.
         */
        if (len > maxCopySize) {
            m = *mp;
            *mp = getPacket(len);
            *replaced = true;
        } else {
            /*
             * Packet should be copied. Try to get
             * one from the mbuf buffer pool.
             */
            m = getPacket(len);
            
            if (m) {
                mbuf_copy_pkthdr(m, *mp);
                mbuf_pkthdr_setheader(m, NULL);
                bcopy(mbuf_data(*mp), mbuf_data(m), len);
            }
            *replaced = false;
        }
    }
    return m;
}
