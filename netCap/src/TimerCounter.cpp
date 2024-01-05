#include "TimerCounter.h"

TimerCounter::TimerCounter()
    : t1(res::zero()) 
    , t2(res::zero())
{

}

TimerCounter::~TimerCounter()
{
}

void TimerCounter::tic()
{
    t1 = clock::now();
}

long long TimerCounter::toc()
{
    t2 = clock::now();
    return std::chrono::duration_cast<res>(t2 - t1).count();
}