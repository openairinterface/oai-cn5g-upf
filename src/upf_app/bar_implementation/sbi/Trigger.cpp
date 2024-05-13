#include "Trigger.hpp"
#include <iostream>

Trigger::Trigger() {}

Trigger::~Trigger() {}

int Trigger::startAlertTimer() {
    alertThread = std::thread(alertTimer);
    alertThread.detach();
    return 0;
}

int Trigger::alertTimer() {
    std::this_thread::sleep_for(std::chrono::seconds(30));
    sendAlert();
    return 0;
}

int Trigger::sendAlert() {
    std::cout << "Alert: Send the packet back to its destination!" << std::endl;
    return 0;
}

