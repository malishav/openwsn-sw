import threading
from   coap   import    coap,                    \
                        coapResource,            \
                        coapDefines as d,        \
                        coapOption as o,         \
                        coapUtils as u,          \
                        coapObjectSecurity as oscoap
import logging.handlers
try:
    from openvisualizer.eventBus import eventBusClient
    import openvisualizer.openvisualizer_utils
except ImportError:
    pass

import cojpDefines
import coseDefines
import aceDefines

log = logging.getLogger('JRC')
log.setLevel(logging.ERROR)
log.addHandler(logging.NullHandler())

import cbor
import binascii
import os
import random
import traceback

# ================ List of resources that can be accessed by any joined node ============
authorizedResources = ['resource1']
# =======================================================================================

# ==== App-layer ID of the JRC as defined by draft-ietf-6tisch-minimal-security-06 ======
JRC_ID = '4a5243'
# =======================================================================================

# ======================== Top Level JRC Class =============================
class JRC():

    def __init__(self):
        self.sixtischNetwork = SixtischNetwork(
            networkKey=u.str2buf(binascii.unhexlify('11111111111111111111111111111111')), # value of K1/K2 from 6TiSCH TD)
            networkKeyIndex=0x01,
            groupPSK='DEADBEEFCAFEDEADBEEFCAFEDEADBEEF',
        )

        self.externalClients = Network(
            joinedNodes= [
                Node(
                    ipAddress='::1',
                    id='636c69656e74',
                    peerID=JRC_ID,
                    pairwisePSK='000102030405060708090A0B0C0D0E0F',
                    aeadAlgorithm=oscoap.AES_CCM_16_64_128()
                ),
            ],
            groupPSK='000102030405060708090A0B0C0D0E0F'
        )

        self.networks = (self.sixtischNetwork, self.externalClients)

        self.coapServer = CoapServer(networks=self.networks)

    def close(self):
        self.coapServer.close()

# =======================================================================================

# =========================== Generic Joined Node =======================================
class Node():

    def __init__(self,
                 ipAddress=None,
                 appSessionKey=None,
                 appCounter=1,
                 context=None,          # oscoap.SecurityContext; used to bootstrap the identifier, if not passed security context is instantiated
                 id=None,               # required when context is None
                 peerID=None,           # required when context is None
                 pairwisePSK=None,      # required when context is None
                 aeadAlgorithm=None,    # required when context is None
                 ):
        self.ipAddress = ipAddress      # IPv6 as a string

        if context is not None:
            assert (id is None and peerID is None and pairwisePSK is None and aeadAlgorithm is None)
            self.id = context.recipientID
            self.context = context
        else:
            assert (id is not None and peerID is not None and pairwisePSK is not None and aeadAlgorithm is not None)
            self.id = id

            self.context = oscoap.SecurityContext(  # deriving a new security context
                masterSecret=binascii.unhexlify(pairwisePSK),
                senderID=binascii.unhexlify(peerID),
                recipientID=binascii.unhexlify(id),
                aeadAlgorithm=aeadAlgorithm
            )

        # if appSessionKey is not explicitly passed, use OSCORE derivation with "ACE" label to HKDF
        if appSessionKey is not None:
            self.appSessionKey = self.context.hkdfDeriveParameter(  # if no app session key is provided, derive a default
                    id=self.id,
                    type='ACE',
                    length=16
            )
        else:
            self.appSessionKey = appSessionKey                      # hex string

        self.appCounter = appCounter                                # integer

    # ======================== public ==========================================

    def setIpAddress(self, ipAddress):
        self.ipAddress = ipAddress

    def getIpAddress(self):
        return self.ipAddress

# =======================================================================================

# ======================= Abstraction of a Network ======================================
class Network():

    def __init__(self, networkPrefix=[], joinedNodes=[], groupPSK=None):
        self.networkPrefix = networkPrefix
        self.joinedNodes = joinedNodes
        self.groupPSK = groupPSK

    # ======================== public ==========================================

    def setNetworkPrefix(self, networkPrefix):
        self.networkPrefix = networkPrefix

    def getNetworkPrefix(self):
        return self.networkPrefix

    def joinedNodesUpdate(self, nodes):
        assert len(self.getNetworkPrefix()) < 9

        for node in nodes:
            hostPart = u.str2buf(binascii.unhexlify(node.id))
            assert len(hostPart) < 9

            ipAddress = [0]*16
            ipAddress[:len(self.getNetworkPrefix())] = self.getNetworkPrefix()
            ipAddress[16-len(hostPart) : 16] = hostPart

            node.setIpAddress(openvisualizer.openvisualizer_utils.formatIPv6Addr(ipAddress))
            self.joinedNodes += [node]

    # id as a string
    def joinedNodesLookup(self, id):
        for node in self.joinedNodes:
            if node.id == id:
                return node
        return None

    # pick a node randomly from the list of all joined nodes, except the one passed as the parameter
    def pickJoinedNodeRandomly(self, skip=None):
        if (len(self.joinedNodes) == 1 and skip == self.joinedNodes[0]) or len(self.joinedNodes) == 0:
            return None

        found = False
        candidate = None

        while found is False:
            candidate = random.choice(self.joinedNodes)
            if candidate != skip:
                found = True
        return candidate

    # ======================== Default context handler based on a group PSK =============================
    # ========================       needs to be registered  with CoAP      =============================
    def securityContextLookup(self, kid):
        # if kid is found in the list of joined nodes, return the appropriate context
        # this is crucial for replay protection
        context=None
        node = self.joinedNodesLookup(kid)
        if node is not None:
            log.info("Node {0} found in joinedNodes. Returning context {1}.".format(binascii.hexlify(node.id), str(node.context)))
            context = node.context
        elif self.groupPSK is not None:
            log.info("Node {0} not found in joinedNodes. Instantiating new context based on the master secret.".format(binascii.hexlify(kid)))

            # if recipientID is not found, create a new tentative context but only add it to the list of joined nodes in the GET
            # handler of the join resource
            context = oscoap.SecurityContext(  # deriving a new security context
                masterSecret=binascii.unhexlify(self.groupPSK),
                senderID=binascii.unhexlify(JRC_ID),
                recipientID=kid,
                aeadAlgorithm=oscoap.AES_CCM_16_64_128()
            )

        return context

# =======================================================================================

# ========================= a 6TiSCH Network Class ======================================
class SixtischNetwork(Network):

    def __init__(self,  dagRootEui64=None, panID=None, networkKey=None, networkKeyIndex=None, networkPrefix=None, joinedNodes=[], groupPSK=''):
        Network.__init__(self, networkPrefix=networkPrefix, joinedNodes=joinedNodes, groupPSK=groupPSK)

        self.dagRootEui64 = dagRootEui64
        self.panID = panID
        self.networkKey = networkKey
        self.networkKeyIndex = networkKeyIndex

    # ======================== public ==========================================

    def setDagRootEui64(self, dagRootEui64):
        self.dagRootEui64 = dagRootEui64

    def getDagRootEui64(self):
        return self.dagRootEui64

    def setPanID(self, panID):
        self.panID = panID

    def getPanID(self):
        return self.panID

    def setNetworkKey(self, networkKey):
        self.networkKey = networkKey

    def getNetworkKey(self):
        return self.networkKey

    def setNetworkKeyIndex(self, networkKeyIndex):
        self.networkKeyIndex = networkKeyIndex

    def getNetworkKeyIndex(self):
        return self.networkKeyIndex

    def getNetworkKeyAndIndex(self):
        return (self.networkKeyIndex, self.networkKey)

    def securityContextLookup(self, kid):
        context = None
        kidBuf = u.str2buf(kid)

        eui64 = kidBuf[:-1]
        senderID = eui64 + [0x01]  # sender ID of JRC is reversed
        recipientID = eui64 + [0x00]

        # if eui-64 is found in the list of joined nodes, return the appropriate context
        # this is important for replay protection
        node = self.joinedNodesLookup(u.buf2str(eui64))

        if node is not None:
            log.info("Node {0} found in joinedNodes. Returning context {1}.".format(node.id, str(node.context)))
            context = node.context
        elif self.groupPSK is not None:
            log.info("Node {0} not found in joinedNodes. Instantiating new context based on the master secret.".format(u.buf2str(eui64)))

            # if eui-64 is not found, create a new tentative context but only add it to the list of joined nodes in the GET
            # handler of the join resource
            context = oscoap.SecurityContext(masterSecret=binascii.unhexlify(self.groupPSK),
                                             senderID=u.buf2str(senderID),
                                             recipientID=u.buf2str(recipientID),
                                             aeadAlgorithm=oscoap.AES_CCM_16_64_128())

        return context

# =======================================================================================

# ====================== CoAP Interface with OpenVisualizer =============================
class CoapServer(eventBusClient.eventBusClient):
    # link-local prefix
    LINK_LOCAL_PREFIX = [0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

    def __init__(self, networks=(None,None)):
        # log
        log.info("create instance")

        (self.sixtischNetwork, self.externalNetwork) = networks
        self.joinResource = JoinResource(
            networkKeyLookupCb=self.sixtischNetwork.getNetworkKeyAndIndex,
            updateJoinedNodesCb=self.sixtischNetwork.joinedNodesUpdate
        )
        self.tokenResource = TokenResource(
            clientAuthorizationCallback=self.externalNetwork.joinedNodesLookup,
            resourceServerLookupCallback=self.sixtischNetwork.pickJoinedNodeRandomly)

        # run CoAP server in testing mode
        # this mode does not open a real socket, rather uses PyDispatcher for sending/receiving messages
        # We interface this mode with OpenVisualizer to run JRC co-located with the DAG root
        self.coapServer = coap.coap(udpPort=d.DEFAULT_UDP_PORT, testing=True)
        self.coapServer.addResource(self.joinResource)
        self.coapServer.addResource(self.tokenResource)
        self.coapServer.addSecurityContextHandler(self.externalNetwork.securityContextLookup)
        self.coapServer.maxRetransmit = 1

        self.coapClient = None

        # store params

        # initialize parent class
        eventBusClient.eventBusClient.__init__(
            self,
            name='JRC',
            registrations=[
                {
                    'sender': self.WILDCARD,
                    'signal': 'getL2SecurityKey',
                    'callback': self._getL2SecurityKey_notif,
                },
                {
                    'sender': self.WILDCARD,
                    'signal': 'registerDagRoot',
                    'callback': self._registerDagRoot_notif
                },
                {
                    'sender': self.WILDCARD,
                    'signal': 'unregisterDagRoot',
                    'callback': self._unregisterDagRoot_notif
                },
            ]
        )

        # local variables
        self.stateLock = threading.Lock()

    # ======================== public ==========================================

    def close(self):
        # nothing to do
        pass

    # ======================== private =========================================

    # ==== handle EventBus notifications

    def _getL2SecurityKey_notif(self, sender, signal, data):
        '''
        Return L2 security key for the network.
        '''
        return {'index' : [self.sixtischNetwork.getNetworkKeyIndex()], 'value' : self.sixtischNetwork.getNetworkKey()}

    def _registerDagRoot_notif(self, sender, signal, data):
        # register for the global address of the DAG root
        self.register(
            sender=self.WILDCARD,
            signal=(
                tuple(data['prefix'] + data['host']),
                self.PROTO_UDP,
                d.DEFAULT_UDP_PORT
            ),
            callback=self._receiveFromMeshOrInternet,
        )

        # register to receive at link-local DAG root's address
        self.register(
            sender=self.WILDCARD,
            signal=(
                tuple(self.LINK_LOCAL_PREFIX + data['host']),
                self.PROTO_UDP,
                d.DEFAULT_UDP_PORT
            ),
            callback=self._receiveFromMeshOrInternet,
        )

        self.sixtischNetwork.setNetworkPrefix(data['prefix'])
        self.sixtischNetwork.setDagRootEui64(data['host'])

    def _unregisterDagRoot_notif(self, sender, signal, data):
        # unregister global address
        self.unregister(
            sender=self.WILDCARD,
            signal=(
                tuple(data['prefix'] + data['host']),
                self.PROTO_UDP,
                d.DEFAULT_UDP_PORT
            ),
            callback=self._receiveFromMeshOrInternet,
        )
        # unregister link-local address
        self.unregister(
            sender=self.WILDCARD,
            signal=(
                tuple(self.LINK_LOCAL_PREFIX + data['host']),
                self.PROTO_UDP,
                d.DEFAULT_UDP_PORT
            ),
            callback=self._receiveFromMeshOrInternet,
        )

        self.sixtischNetwork.setDagRootEui64(None)
        self.sixtischNetwork.setNetworkPrefix(None)

    def _receiveFromMeshOrInternet(self, sender, signal, data):
        '''
        Receive packet from the mesh destined for JRC's CoAP server.
        Forwards the packet to the virtual CoAP server running in test mode (PyDispatcher).
        '''
        (srcIPv6, dataDict) = data
        srcUdpPort = dataDict['udp_src_port']
        appData = dataDict['app_payload']

        sender = openvisualizer.openvisualizer_utils.formatIPv6Addr(srcIPv6)

        # create an ephemeral coap client object to (re)transmit the message on the event bus of the coap server
        self.coapClient = coap.coap(ipAddress=sender, udpPort=srcUdpPort , testing=True, receiveCallback=self._receiveFromCoAP)
        self.coapClient.socketUdp.sendUdp(destIp='', destPort=d.DEFAULT_UDP_PORT, msg=appData) # low level forward of the CoAP message
        self.coapClient.close()
        return True

    def _receiveFromCoAP(self, timestamp, sender, data):
        '''
        Receive CoAP response and forward it to the mesh network.
        Appends UDP and IPv6 headers to the CoAP message and forwards it on the Eventbus towards the mesh.
        '''
        # UDP
        udplen = len(data) + 8

        udp = u.int2buf(sender[1], 2) # src port
        udp += u.int2buf(self.coapClient.udpPort,2)  # dest port
        udp += [udplen >> 8, udplen & 0xff]  # length
        udp += [0x00, 0x00]  # checksum
        udp += data

        # destination address of the packet is CoAP client's IPv6 address (address of the mote)
        dstIpv6Address = u.ipv6AddrString2Bytes(self.coapClient.ipAddress)
        assert len(dstIpv6Address)==16
        # source address of the packet is DAG root's IPV6 address
        # use the same prefix (link-local or global) as in the destination address
        srcIpv6Address = dstIpv6Address[:8]
        srcIpv6Address += self.sixtischNetwork.getDagRootEui64()
        assert len(srcIpv6Address)==16

        # CRC See https://tools.ietf.org/html/rfc2460.

        udp[6:8] = openvisualizer.openvisualizer_utils.calculatePseudoHeaderCRC(
            src=srcIpv6Address,
            dst=dstIpv6Address,
            length=[0x00, 0x00] + udp[4:6],
            nh=[0x00, 0x00, 0x00, 17], # UDP as next header
            payload=udp,
        )

        # IPv6
        ip = [6 << 4]  # v6 + traffic class (upper nybble)
        ip += [0x00, 0x00, 0x00]  # traffic class (lower nibble) + flow label
        ip += udp[4:6]  # payload length
        ip += [17]  # next header (protocol); UDP=17
        ip += [64]  # hop limit (pick a safe value)
        ip += srcIpv6Address  # source
        ip += dstIpv6Address  # destination
        ip += udp

        # if destination IPv6 does not match the network prefix, and is not link-local, send to Internet
        # special case is when sending from the TUN interface that has the same prefix as the mesh network but ends in 0x01
        if (dstIpv6Address[:8] != self.sixtischNetwork.getNetworkPrefix() and dstIpv6Address[:8] != self.LINK_LOCAL_PREFIX) \
                or (dstIpv6Address == self.sixtischNetwork.getNetworkPrefix() + [0, 0, 0, 0, 0, 0, 0, 1]):
            self.dispatch(
                signal='v6ToInternet',
                data=ip
            )
        else:
            self.dispatch(
                signal        = 'v6ToMesh',
                data          = ip
            )

# =======================================================================================

# ======================== Implementation of CoAP Join Resource =========================
class JoinResource(coapResource.coapResource):

    def __init__(self, networkKeyLookupCb, updateJoinedNodesCb):
        # initialize parent class
        coapResource.coapResource.__init__(
            self,
            path = 'j',
        )

        self.addSecurityBinding((None, [d.METHOD_POST]))  # security context should be returned by the callback

        self.networkKeyLookupCb = networkKeyLookupCb
        self.updateJoinedNodesCb = updateJoinedNodesCb

    def POST(self,options=[], payload=[]):
        respCode        = d.COAP_RC_2_04_CHANGED
        respOptions     = []

        assert self.networkKeyLookupCb
        (id, key) = self.networkKeyLookupCb()
        link_layer_keyset = [id, u.buf2str(key)]

        configuration = {}

        configuration[cojpDefines.COJP_PARAMETERS_LABELS_LLKEYSET]   = link_layer_keyset
        configuration_serialized = cbor.dumps(configuration)

        respPayload     = [ord(b) for b in configuration_serialized]

        #objectSecurity = oscoap.objectSecurityOptionLookUp(options)
        #assert objectSecurity

        # joinedNodes += [ Node(
        #                       id=u.buf2str(objectSecurity.kid[:8]),
        #                       context=objectSecurity.context,
        #                       appSessionKey=objectSecurity.context.hkdfDeriveParameter(
        #                                                           id=objectSecurity.context.recipientID,
        #                                                           type='ACE',
        #                                                           length=16),
        #                       appCounter=1)
        #                ]

        return (respCode,respOptions,respPayload)

# ==================== Implementation of /token resource to hand out ACE authorization tokens =====================
class TokenResource(coapResource.coapResource):

    def __init__(self, clientAuthorizationCallback, resourceServerLookupCallback):
        # initialize parent class
        coapResource.coapResource.__init__(
            self,
            path = 'token',
        )

        self.addSecurityBinding((None, [d.METHOD_POST]))  # security context should be returned by the callback

        self.clientAuthorizationCallback = clientAuthorizationCallback
        self.resourceServerLookupCallback = resourceServerLookupCallback

    def POST(self,options=[], payload=[]):
        respOptions     = []
        respPayload     = []

        try:
            objectSecurity = oscoap.objectSecurityOptionLookUp(options)

            # the request MUST come be received over a secure OSCORE channel
            if objectSecurity is None:
                log.info("Client requesting access over unprotected transport.")
                raise AceUnauthorized

            clientId =  binascii.hexlify(u.buf2str(objectSecurity.kid))

            # if the client that is requesting an access token is not in the list of joined nodes, consider it unauthorized
            assert self.clientAuthorizationCallback
            client = self.clientAuthorizationCallback(clientId)

            if client is None:
                log.info(
                    "Client {0} not found in the list of authorized nodes.".format(clientId))
                raise AceUnauthorized
            # else: every joined node is considered authorized

            log.info("Client {0}, deemed authorized, requests an access token.".format(clientId))

            # we don't use aud parameter for the moment, RS is selected randomly by AS from the list of joined nodes
            # this allows the JRC to act as a discovery server, allowing the client to specify the resource it is interested in
            # and the JRC to communicate to the cliient which RS hosts such a resource
            # client contacts the RS by constructing its IPv6 address, based on RS's identifier (EUI-64), assuming they are
            # in the same 6TiSCH network
            assert self.resourceServerLookupCallback
            resourceServer = self.resourceServerLookupCallback()

            # proceed by checking the request format
            contentFormat = self.lookupContentFormat(options)
            if contentFormat is None or contentFormat.format != d.FORMAT_CBOR:
                log.info("Request is malformed: Content-Format is not set to CBOR.")
                raise AceBadRequest

            request = cbor.loads(u.buf2str(payload))
            log.debug("Request decoded as: {0}".format(request))

            if request[aceDefines.ACE_PARAMETERS_LABELS_GRANT_TYPE] != aceDefines.ACE_CBOR_ABBREVIATIONS_CLIENT_CREDENTIALS:
                log.info("Request is malformed: grant_type is not set to \"client_credentials\".")
                raise AceBadRequest

            # scope parameter is necessary for now
            if request[aceDefines.ACE_PARAMETERS_LABELS_SCOPE] not in authorizedResources:
                log.info("Request scope {0}: deemed unauthorized.".format(request[aceDefines.ACE_PARAMETERS_LABELS_SCOPE]))
                raise AceUnauthorized

            # construct the access token

            # Step 1. construct the CNF (confirmation) claim
            cnf_value = {
                aceDefines.ACE_CWT_CNF_COSE_KEY : {
                    coseDefines.KEY_LABEL_KTY           : coseDefines.KEY_VALUE_SYMMETRIC,
                    # TODO assign IDs so they are unique
                    coseDefines.KEY_LABEL_CLIENT_ID     : binascii.unhexlify('00'),
                    coseDefines.KEY_LABEL_SERVER_ID     : binascii.unhexlify('01'),
                    coseDefines.KEY_LABEL_K             : os.urandom(16),  # generate random 128-bit key
                }
            }

            # Step 2. Construct CWT claims set
            cwt_claims_set = {}
            # claim to RS is implicitly known and corresponds to 'all-resources'
            cwt_claims_set[aceDefines.ACE_PARAMETERS_LABELS_CNF] = cnf_value

            # Step 3. Construct CWT by encrypting in a COSE_Encrypt0 wrapper the CWT claims set

            # COSE_Encrypt0 protected bucket
            cwt_protected = ''

            # COSE_Encrypt0 unprotected bucket

            # nonce is appCounter prepended with 13 - len(appCounter) zeros
            nonce = u.buf2str(u.int2buf(resourceServer.appCounter, 13))
            cwt_unprotected = {
                coseDefines.COMMON_HEADER_PARAMETERS_PIV: resourceServer.appCounter
            }

            # Don't forget to increment the appCounter
            resourceServer.appCounter += 1

            # COSE Enc_structure from https://tools.ietf.org/html/draft-ietf-cose-msg-24#section-5.3
            encStructure = [
                unicode('Encrypt0'),
                cwt_protected,     # protected bucket
                '',                # additional data
            ]

            # FIXME code below is used for testing, appSessionKey derivation is done once the node joins the network
            # the key to encrypt the CWT is derived from the OSCORE master secret, with info set to 'ACE'
            key = resourceServer.context.hkdfDeriveParameter(
                                               id=resourceServer.context.senderID,
                                               type='ACE',
                                               length=16)

            # generate the ciphertext by encrypting with the CCM algorithm
            ciphertext = oscoap.AES_CCM_16_64_128().authenticateAndEncrypt(aad=cbor.dumps(encStructure),
                                                                           plaintext=cbor.dumps(cwt_claims_set),
                                                                           key=key,
                                                                           nonce=nonce)

            # Step 4. Construct the CWT object
            cwt = [
                cwt_protected,
                cwt_unprotected,
                ciphertext
            ]

            access_token = {}
            access_token[aceDefines.ACE_PARAMETERS_LABELS_ACCESS_TOKEN] = cbor.dumps(cwt)
            access_token[aceDefines.ACE_PARAMETERS_LABELS_CNF] = cnf_value
            access_token[aceDefines.ACE_PARAMETERS_LABELS_AUD] = "coap://[{0}]".format(resourceServer.getIpAddress())

            access_token_serialized = cbor.dumps(access_token)

            respCode = d.COAP_RC_2_04_CHANGED
            respPayload = [ord(b) for b in access_token_serialized]
            respOptions += [o.ContentFormat(cformat=[d.FORMAT_CBOR])]
        except AceBadRequest:
            respCode = d.COAP_RC_4_00_BADREQUEST
        except (TypeError, NameError, ValueError, KeyError):
            # in case of the built-in exceptions, the request is not properly formatted, send 4.00
            log.debug("Exception occured while processing the request:\n===============================\n{0}\n===============================".format(traceback.format_exc()))
            respCode = d.COAP_RC_4_00_BADREQUEST
        except AceUnauthorized:
            respCode = d.COAP_RC_4_01_UNAUTHORIZED
        except:
            log.debug(
                "Exception occured while processing the request:\n===============================\n{0}\n===============================".format(traceback.format_exc()))
            raise
        return (respCode,respOptions,respPayload)

    # ======================== private =========================================

    def lookupContentFormat(self, options=[]):
        for option in options:
            if isinstance(option, o.ContentFormat):
                return option
        return None

# =======================================================================================

# ============================ Custom Exceptions ========================================
class AceException(Exception):
    def __init__(self, reason=''):
        assert type(reason) == str

        # store params
        self.reason = reason

    def __str__(self):
        return '{0}(reason={1})'.format(self.__class__.__name__, self.reason)

class AceUnauthorized(AceException):
    pass

class AceBadRequest(AceException):
    pass

# =======================================================================================

# ============================ main =========================================

if __name__ == "__main__":

    fileLogger = logging.handlers.RotatingFileHandler(
        filename    = 'test.log',
        mode        = 'w',
        backupCount = 5,
    )
    fileLogger.setFormatter(
        logging.Formatter(
            '%(asctime)s [%(name)s:%(levelname)s] %(message)s'
        )
    )

    consoleLogger = logging.StreamHandler()
    consoleLogger.setLevel(logging.DEBUG)

    for loggerName in [
            'coap',
            'coapOption',
            'coapUri',
            'coapTransmitter',
            'coapMessage',
            'socketUdpReal',
        ]:
        temp = logging.getLogger(loggerName)
        temp.setLevel(logging.DEBUG)
        temp.addHandler(fileLogger)
        temp.addHandler(consoleLogger)
    
    log = logging.getLogger('JRC')
    log.setLevel(logging.DEBUG)
    log.addHandler(fileLogger)
    log.addHandler(consoleLogger)
 
    c = coap.coap()

    joinResource = joinResource()

    c.addResource(joinResource)

    c.addSecurityContextHandler(JRCSecurityContextLookup) # register callback


    raw_input('\n\nServer running. Press Enter to close.\n\n')
    
    c.close()

