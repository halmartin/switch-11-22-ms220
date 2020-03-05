#include <iostream>
#include <algorithm>
#include <string>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>

#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#include <libecap/common/registry.h>
#include <libecap/common/errors.h>
#include <libecap/common/message.h>
#include <libecap/common/header.h>
#include <libecap/common/names.h>
#include <libecap/common/named_values.h>
#include <libecap/host/host.h>
#include <libecap/adapter/service.h>
#include <libecap/adapter/xaction.h>
#include <libecap/host/xaction.h>

#ifdef HAVE_CONFIG_H
#include "autoconf.h"
#endif

#define PACKAGE_VERSION "1.0"
#define PACKAGE_NAME "squid_ssl_sniffer"

#define SQUID_SNIFFER_CHUNK_SIZE 8192
#define SQUID_SNIFFER_PRINT_BUFFER_SIZE 100

namespace Adapter { // not required, but adds clarity

using libecap::size_type;

class Service: public libecap::adapter::Service {
    public:
        // About
        virtual std::string uri() const; // unique across all vendors
        virtual std::string tag() const; // changes with version and config
        virtual void describe(std::ostream &os) const; // free-format info

        // Configuration
        virtual void configure(const libecap::Options &cfg);
        virtual void reconfigure(const libecap::Options &cfg);
        void setOne(const libecap::Name &name, const libecap::Area &valArea);

        // Lifecycle
        virtual void start(); // expect makeXaction() calls
        virtual void stop(); // no more makeXaction() calls until start()
        virtual void retire(); // no more makeXaction() calls

        // Scope (XXX: this may be changed to look at the whole header)
        virtual bool wantsUrl(const char *url) const;

        // Work
        virtual MadeXactionPointer makeXaction(libecap::host::Xaction *hostx);

    public:
        // Configuration storage
        std::string log_fpath, iface_fpath;
        FILE* log_fd, *iface_fd;
        bool registered;
};


// Calls Service::setOne() for each host-provided configuration option.
// See Service::configure().
class Cfgtor: public libecap::NamedValueVisitor {
    public:
        Cfgtor(Service &aSvc): svc(aSvc) {}
        virtual void visit(const libecap::Name &name, const libecap::Area &value) {
            svc.setOne(name, value);
        }
        Service &svc;
};


class Xaction: public libecap::adapter::Xaction {
    public:
        Xaction(libecap::shared_ptr<Service> s, libecap::host::Xaction *x);
        virtual ~Xaction();

        // meta-information for the host transaction
        virtual const libecap::Area option(const libecap::Name &name) const;
        virtual void visitEachOption(libecap::NamedValueVisitor &visitor) const;

        // lifecycle
        virtual void start();
        virtual void stop();

        // adapted body transmission control
        virtual void abDiscard();
        virtual void abMake();
        virtual void abMakeMore();
        virtual void abStopMaking();

        // adapted body content extraction and consumption
        virtual libecap::Area abContent(size_type offset, size_type size);
        virtual void abContentShift(size_type size);

        // virgin body state notification
        virtual void noteVbContentDone(bool atEnd);
        virtual void noteVbContentAvailable();

    protected:
        int pushToFile(std::string &chunk) const; // converts vb to ab
        int pushToIoctl(std::string &chunk) const; // converts vb to ab
        void stopVb(); // stops receiving vb (if we are receiving it)
        libecap::host::Xaction *lastHostCall(); // clears hostx

    private:
        libecap::shared_ptr<const Service> service; // configuration access
        libecap::host::Xaction *hostx; // Host transaction rep

        std::string buffer; // for content adaptation

        typedef enum { opUndecided, opOn, opComplete, opNever } OperationState;
        OperationState receivingVb;
        OperationState sendingAb;
        bool _is_req, _is_header;
        std::string _client;
};

static const std::string CfgErrorPrefix =
    "Modifying Adapter: configuration error: ";

} // namespace Adapter

std::string Adapter::Service::uri() const {
    return "ecap://meraki.com/ecap/services/squid_ssl_sniffer";
}

std::string Adapter::Service::tag() const {
    return PACKAGE_VERSION;
}

void Adapter::Service::describe(std::ostream &os) const {
    os << "A modifying adapter from " << PACKAGE_NAME << " v" << PACKAGE_VERSION;
}

void Adapter::Service::configure(const libecap::Options &cfg) {
    Cfgtor cfgtor(*this);

    cfg.visitEachOption(cfgtor);
    log_fd = NULL;

    if (iface_fpath == "") {
        throw libecap::TextException(CfgErrorPrefix +
            "Logfile path not given: LOG: " + log_fpath + " IFACE: " + iface_fpath);
    }
    if ((log_fpath != "") && ((log_fd = fopen(log_fpath.c_str(), "a+")) == NULL)) {
        throw libecap::TextException(CfgErrorPrefix +
            "Logfile could not be opened | " + log_fpath);
    }
    if ((iface_fd = fopen(iface_fpath.c_str(), "a+")) < 0) {
        throw libecap::TextException(CfgErrorPrefix +
            "Interface could not be opened | " + iface_fpath);
    }
}

void Adapter::Service::reconfigure(const libecap::Options &cfg) {
    configure(cfg);
}

void Adapter::Service::setOne(const libecap::Name &name, const libecap::Area &valArea) {
    const std::string value = valArea.toString();
    if (name == "log") {
        log_fpath = value;
    } else if (name == "iface") {
        iface_fpath = value;
    } else if (name.assignedHostId()) {
        ; // skip host-standard options we do not know or care about
    } else {
        throw libecap::TextException(CfgErrorPrefix +
            "unsupported configuration parameter: " + name.image());
    }
}

void Adapter::Service::start() {
    libecap::adapter::Service::start();
    // custom code would go here, but this service does not have one
}

void Adapter::Service::stop() {
    // custom code would go here, but this service does not have one
    libecap::adapter::Service::stop();
}

void Adapter::Service::retire() {
    // custom code would go here, but this service does not have one
    libecap::adapter::Service::stop();
}

bool Adapter::Service::wantsUrl(const char *) const {
    return true; // no-op is applied to all messages
}

Adapter::Service::MadeXactionPointer
Adapter::Service::makeXaction(libecap::host::Xaction *hostx) {
    return Adapter::Service::MadeXactionPointer(
        new Adapter::Xaction(std::tr1::static_pointer_cast<Service>(self), hostx));
}


Adapter::Xaction::Xaction(libecap::shared_ptr<Service> aService,
    libecap::host::Xaction *x):
    service(aService),
    hostx(x),
    receivingVb(opUndecided), sendingAb(opUndecided) {
}

Adapter::Xaction::~Xaction() {
    if (libecap::host::Xaction *x = hostx) {
        hostx = 0;
        x->adaptationAborted();
    }
}

const libecap::Area Adapter::Xaction::option(const libecap::Name &) const {
    return libecap::Area(); // this transaction has no meta-information
}

void Adapter::Xaction::visitEachOption(libecap::NamedValueVisitor &) const {
    // this transaction has no meta-information to pass to the visitor
}

void Adapter::Xaction::start() {
    Must(hostx);
    if (hostx->virgin().body()) {
        receivingVb = opOn;
        hostx->vbMake(); // ask host to supply virgin body
    } else {
        // we are not interested in vb if there is not one
        receivingVb = opNever;
    }

    /* adapt message header */

    libecap::shared_ptr<libecap::Message> adapted = hostx->virgin().clone();
    Must(adapted != 0);

    // delete ContentLength header because we may change the length
    // unknown length may have performance implications for the host
    //adapted->header().removeAny(libecap::headerContentLength);

    //Write payload to interface for processing
    std::string payload = adapted->header().image().toString();
    _client = hostx->option(libecap::metaClientConn).toString();

    //Write connection info to log
    _is_header = true;
    int idx = payload.find(' ');
    if (idx > 0) {
        std::string field = payload.substr(0, idx);
        _is_req = (field.find("HTTP") == std::string::npos);
        std::string msg = (_is_req ? "Request " : "Response ") + field + "\n";
        pushToFile(msg);
    } else {
        std::string failed = "Failed to push for op:\n " + payload + "\n";
        pushToFile(failed);
    }

    pushToIoctl(payload);

    if (!adapted->body()) {
        sendingAb = opNever; // there is nothing to send
        lastHostCall()->useAdapted(adapted);
    } else {
        hostx->useAdapted(adapted);
    }
}

void Adapter::Xaction::stop() {
    hostx = 0;
    // the caller will delete
}

void Adapter::Xaction::abDiscard()
{
    Must(sendingAb == opUndecided); // have not started yet
    sendingAb = opNever;
    // we do not need more vb if the host is not interested in ab
    stopVb();
}

void Adapter::Xaction::abMake()
{
    Must(sendingAb == opUndecided); // have not yet started or decided not to send
    Must(hostx->virgin().body()); // that is our only source of ab content

    // we are or were receiving vb
    Must(receivingVb == opOn || receivingVb == opComplete);

    sendingAb = opOn;
    if (!buffer.empty())
        hostx->noteAbContentAvailable();
}

void Adapter::Xaction::abMakeMore()
{
    Must(receivingVb == opOn); // a precondition for receiving more vb
    hostx->vbMakeMore();
}

void Adapter::Xaction::abStopMaking()
{
    sendingAb = opComplete;
    // we do not need more vb if the host is not interested in more ab
    stopVb();
}


libecap::Area Adapter::Xaction::abContent(size_type offset, size_type size) {
    Must(sendingAb == opOn || sendingAb == opComplete);
    return libecap::Area::FromTempString(buffer.substr(offset, size));
}

void Adapter::Xaction::abContentShift(size_type size) {
    Must(sendingAb == opOn || sendingAb == opComplete);
    buffer.erase(0, size);
}

void Adapter::Xaction::noteVbContentDone(bool atEnd)
{
    Must(receivingVb == opOn);
    stopVb();
    if (sendingAb == opOn) {
        hostx->noteAbContentDone(atEnd);
        sendingAb = opComplete;
    }
}

void Adapter::Xaction::noteVbContentAvailable()
{
    Must(receivingVb == opOn);

    char res[SQUID_SNIFFER_PRINT_BUFFER_SIZE];
    _is_header = false;
    const libecap::Area vb = hostx->vbContent(0, libecap::nsize); // get all vb
    std::string chunk = vb.toString(); // expensive, but simple
    hostx->vbContentShift(vb.size); // we have a copy; do not need vb any more
    int chunk_size = SQUID_SNIFFER_CHUNK_SIZE;
    for (int i = 0; i < chunk.size(); i+= chunk_size) {
        unsigned int min = i;
        unsigned int max = i + chunk_size;
        if (min > chunk.size())
            break;
        if (max > chunk.size())
            max = chunk.size();
        std::string content = chunk.substr(min, max);
        int num = pushToIoctl(content);
        if (num < chunk_size) {
            snprintf(res, SQUID_SNIFFER_PRINT_BUFFER_SIZE, "Wrote %d/%d\n", num, chunk_size);
            std::string out(res);
            pushToFile(out);
        }
    }

    snprintf(res, SQUID_SNIFFER_PRINT_BUFFER_SIZE, "%ld", chunk.size());
    std::string msg = std::string(_is_req ? "Request" : "Response") + std::string(" Body | Len ") + std::string(res) + "\n";

    pushToFile(msg);
    buffer += chunk; // buffer what we got

    if (sendingAb == opOn)
        hostx->noteAbContentAvailable();
}

int Adapter::Xaction::pushToFile(std::string &chunk) const {
    if (!service->log_fd) return 0;
    int returned = fprintf(service->log_fd, "%s %d %d|%s", _client.c_str(), _is_req, _is_header, chunk.c_str());
    fflush(service->log_fd);
    return returned;
}

int Adapter::Xaction::pushToIoctl(std::string &chunk) const {
    std::string cpy = _client + std::string(_is_req ? " 1 " : " 0 ") + std::string(_is_header ? " 1" : " 0") + "|" + chunk;
    int ret = fwrite(cpy.c_str(), 1, cpy.size(), service->iface_fd);
    fflush(service->iface_fd);

    std::string msg;
    struct sockaddr_un serv_addr;
    int sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        msg = "socket error\n"; pushToFile(msg);
        goto push_done;
    }

    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sun_family = AF_UNIX;
    strcpy(serv_addr.sun_path, "/tmp/snr_server");

    if (connect(sockfd, (struct sockaddr *)&serv_addr, SUN_LEN(&serv_addr)) < 0) {
        msg = "connect error\n"; pushToFile(msg);
        goto push_done;
    }

    // send data through socket
    send(sockfd, cpy.c_str(), cpy.size(), 0);
push_done:
    close(sockfd);
    return ret;
}

// tells the host that we are not interested in [more] vb
// if the host does not know that already
void Adapter::Xaction::stopVb() {
    if (receivingVb == opOn) {
        hostx->vbStopMaking(); // we will not call vbContent() any more
        receivingVb = opComplete;
    } else {
        // we already got the entire body or refused it earlier
        Must(receivingVb != opUndecided);
    }
}

// this method is used to make the last call to hostx transaction
// last call may delete adapter transaction if the host no longer needs it
// TODO: replace with hostx-independent "done" method
libecap::host::Xaction *Adapter::Xaction::lastHostCall() {
    libecap::host::Xaction *x = hostx;
    Must(x);
    hostx = 0;
    return x;
}

// create the adapter and register with libecap to reach the host application
static const bool Registered =
    libecap::RegisterVersionedService(new Adapter::Service);
