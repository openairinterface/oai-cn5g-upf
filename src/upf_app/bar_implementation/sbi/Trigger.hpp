#ifndef TRIGGER_HPP
#define TRIGGER_HPP

#include <thread>
#include <chrono>

class Trigger {
public:
    Trigger(int delay); // Add a constructor taking the delay as a parameter
    ~Trigger();
    int startAlertTimer();
    static int sendAlert();

private:
    std::thread alertThread;
    int delay; // Store the delay as a member variable
    int alertTimer();
};

#endif // TRIGGER_HPP
