#ifndef TRIGGER_HPP
#define TRIGGER_HPP

#include <thread>
#include <chrono>

class Trigger {
public:
    Trigger();
    ~Trigger();
    int startAlertTimer();
    static int sendAlert();

private:
    std::thread alertThread;
    static int alertTimer(int delay);
};

#endif // TRIGGER_HPP

