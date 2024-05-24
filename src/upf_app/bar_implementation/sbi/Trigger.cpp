#include "Trigger.hpp"
#include <iostream>

Trigger::Trigger(int delay) : delay(delay) {} // Initialize delay in the constructor

Trigger::~Trigger() {}

int Trigger::startAlertTimer() {
    alertThread = std::thread(&Trigger::alertTimer, this); // Use the current object to call alertTimer
    alertThread.detach();
    return 0;
}

int Trigger::alertTimer() {
    std::this_thread::sleep_for(std::chrono::seconds(delay)); // Use delay to determine the sleep duration
    sendAlert();
    return 0;
}

int Trigger::sendAlert() {
    std::cout << "Alert: Send the packet back to its destination!" << std::endl;
    return 0;
}
