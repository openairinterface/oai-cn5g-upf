#include <memory>

class QosConfigManager {
public:
    static QosConfigManager& getInstance() {
        static QosConfigManager instance;
        return instance;
    }

    void initialize(bool enableBpfDatapath, bool enableQos) {
        enable_bpf_datapath = enableBpfDatapath;
        enable_qos = enableQos;
    }

    bool isBpfDatapathEnabled() const {
        return enable_bpf_datapath;
    }

    bool isQosEnabled() const {
        return enable_bpf_datapath && enable_qos;
    }


private:
    bool enable_bpf_datapath = false;
    bool enable_qos = false;

    // Private constructor and assignment operators for Singleton
    QosConfigManager() = default;
    QosConfigManager(const QosConfigManager&) = delete;
    QosConfigManager& operator=(const QosConfigManager&) = delete;
};
