#ifndef TIME_COUNTER_H_A1B02G1
#define TIME_COUNTER_H_A1B02G1
#include <iostream>
#include <chrono>
class TimerCounter
{
public:
    TimerCounter();

    ~TimerCounter();

    void tic();
    long long toc();

private:
    typedef std::chrono::high_resolution_clock clock;
    typedef std::chrono::milliseconds res;

    clock::time_point t1;
    clock::time_point t2;
};

#endif // !TIME_COUNTER_H_A1B02G1
