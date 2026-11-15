#include "vpn/accounting.h"

#include "vpn/radius.h"

#include <stdexcept>
#include <utility>

namespace vpn {

RadiusAccounting::RadiusAccounting(RadiusServerConfig config)
    : client_(std::make_unique<RadiusClient>(std::move(config))) {}

RadiusAccounting::~RadiusAccounting() = default;

bool RadiusAccounting::send(AcctStatus status,
                            const AcctRecord& record,
                            std::string* error) {
    if (!client_) {
        if (error) {
            *error = "radius accounting is not initialized";
        }
        return false;
    }
    return client_->send_accounting(status, record, error);
}

} // namespace vpn