import AuthenticationServices
import BigInt
import Combine
import Flow
import SafariServices
import NIO

public let fcl = FCL.shared

public final class FCL: NSObject {
    public static let shared = FCL()

    public var delegate: FCLDelegate?

    public var config = Config()

    private var providers: [FCLProvider] = [.dapper, .blocto]

    private var session: ASWebAuthenticationSession?

    private let api = API()
    
    private lazy var evGroup: MultiThreadedEventLoopGroup = {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        return group
    }()

    @Published var currentUser: User?

    private lazy var defaultAddressRegistry = AddressRegistry()

    internal var cancellables = Set<AnyCancellable>()

    // MARK: - Back Channel

    public func config(appName: String,
                       appIcon: String,
                       location: String,
                       walletNode: String,
                       accessNode: String,
                       scope: String,
                       authn: String) {
        _ = config.put(key: .wallet, value: walletNode)
            .put(key: .accessNode, value: accessNode)
            .put(key: .title, value: appName)
            .put(key: .icon, value: appIcon)
            .put(key: .icon, value: appIcon)
            .put(key: .scope, value: scope)
            .put(key: .authn, value: authn)
            .put(key: .location, value: location)
    }

    public func unauthenticate() {
        // TODO: implement this
        currentUser = nil
    }

    func reauthenticate() -> Future<FCLResponse, Error> {
        // TODO: implement this
        unauthenticate()
        return authn()
    }

    internal func closeSession() {
        DispatchQueue.main.async {
            self.session?.cancel()
        }
    }

    func authz(presignable: PreSignable) -> Future<String, Error> {
        return Future { [weak self] promise in
            guard let self = self, let currentUser = self.currentUser, currentUser.loggedIn else {
                promise(.failure(Flow.FError.unauthenticated))
                return
            }

            flow.accessAPI.getLatestBlock(sealed: true).flatMap { block -> EventLoopFuture<Interaction> in
                return self.comsume(block: block, presignable: presignable)
            }.flatMap { ix -> EventLoopFuture<Flow.ID> in
                guard let tx = try? self.toFlowTransaction(ix: ix) else {
                    return self.evGroup.next().makeFailedFuture(FCLError.generic)
                }
                
                return try! flow.sendTransaction(signedTransaction: tx)
            }.whenComplete { result in
                switch result {
                case .success(let txId):
                    promise(.success(txId.hex))
                case .failure(let err):
                    promise(.failure(err))
                }
            }
        }
    }
    
    private func comsume(block: Flow.Block, presignable: PreSignable) -> EventLoopFuture<Interaction> {
        let ev = evGroup.next()
        let promise = ev.makePromise(of: Interaction.self)
        
        guard let service = service(forType: .authz), let endpoint = service.endpoint else {
            return ev.makeFailedFuture(FCLError.generic)
        }
        
        let blockId = block.id.hex
        var object = presignable
        object.interaction.message.refBlock = blockId
        guard let data = try? JSONEncoder().encode(object) else {
            return ev.makeFailedFuture(FCLError.generic)
        }
        
        self.api.execHttpPost(url: endpoint, params: service.params, data: data)
            .flatMap { response -> Future<Interaction, Error> in
                let signableUsers = self.resolvePreAuthz(resp: response)
                var accounts = [String: SignableUser]()
                object.interaction.authorizations.removeAll()
                signableUsers.forEach { user in
                    let tempID = [user.addr!, String(user.keyID!)].joined(separator: "-")
                    var temp = user
                    temp.tempID = tempID

                    if accounts.keys.contains(tempID) {
                        accounts[tempID]?.role.merge(role: temp.role)
                    }
                    accounts[tempID] = temp

                    if user.role.proposer {
                        object.interaction.proposer = tempID
                    }

                    if user.role.payer {
                        object.interaction.payer = tempID
                    }

                    if user.role.authorizer {
                        object.interaction.authorizations.append(tempID)
                    }
                }

                object.interaction.accounts = accounts
                return self.resolveSignatures(interaction: object.interaction)
            }.sink { completion in
                if case let .failure(error) = completion {
                    print(error)
                    promise.fail(error)
                }
            } receiveValue: { ix in
                promise.succeed(ix)
            }.store(in: &cancellables)
        
        return promise.futureResult
    }

    func resolvePreAuthz(resp: AuthnResponse) -> [SignableUser] {
        var axs = [(role: String, service: Service)]()
        if let proposer = resp.data?.proposer {
            axs.append(("PROPOSER", proposer))
        }
        for az in resp.data?.payer ?? [] {
            axs.append(("PAYER", az))
        }
        for az in resp.data?.authorization ?? [] {
            axs.append(("AUTHORIZER", az))
        }

        return axs.compactMap { role, service in

            guard let address = service.identity?.address,
                  let keyId = service.identity?.keyId else {
                return nil
            }

            return SignableUser(tempID: [address, String(keyId)].joined(separator: "|"),
                                addr: address,
                                keyID: keyId,
                                role: Role(proposer: role == "PROPOSER",
                                           authorizer: role == "AUTHORIZER",
                                           payer: role == "PAYER",
                                           param: nil)) { data in
                fcl.api.execHttpPost(service: service, data: data).eraseToAnyPublisher()
            }
        }
    }

    func authorization() -> Future<AuthnResponse, Error> {
        return Future { [weak self] promise in
            guard let self = self, let currentUser = self.currentUser, currentUser.loggedIn else {
                promise(.failure(Flow.FError.unauthenticated))
                return
            }

            guard let url = self.service(forType: .authz)?.endpoint else {
                return
            }

            self.api.execHttpPost(url: url)
                .sink { completion in
                    if case let .failure(error) = completion {
                        promise(.failure(error))
                    }
                } receiveValue: { model in
                    promise(.success(model))
                }
                .store(in: &self.cancellables)
        }
    }

    public func authn() -> Future<FCLResponse, Error> {
        return Future { promise in
            guard let endpoint = self.config.get(key: .authn),
                  let url = URL(string: endpoint) else {
                return promise(.failure(Flow.FError.urlEmpty))
            }
            self.api.execHttpPost(url: url)
                .map { response -> FCLResponse in
                    self.currentUser = self.buildUser(authn: response)
                    return FCLResponse(address: response.data?.addr)
                }
                .receive(on: DispatchQueue.main)
                .sink { _ in
                    self.closeSession()
                } receiveValue: { model in
                    promise(.success(model))
                }.store(in: &self.cancellables)
        }
    }

    // MARK: - Session

    internal func openAuthenticationSession(service: Service) throws {
        guard let endpoint = service.endpoint,
              let url = buildURL(url: endpoint, params: service.params) else {
            throw FCLError.invalidSession
        }

        DispatchQueue.main.async {
            self.delegate?.hideLoading()
            let session = ASWebAuthenticationSession(url: url,
                                                     callbackURLScheme: nil) { _, _ in
                fcl.api.canContinue = false
            }
            self.session = session
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = !url.path.contains("authn")
            session.start()
        }
    }

    // MARK: - Util

    private func buildUser(authn: AuthnResponse) -> User? {
        guard let address = authn.data?.addr else { return nil }
        return User(addr: Flow.Address(hex: address),
                    loggedIn: true,
                    services: authn.data?.services)
    }
    
    private func service(forType type: FCLServiceType) -> Service? {
        guard let services = currentUser?.services else {
            return nil
        }
        
        return services.first(where: { service in
            service.type == type
        })
    }
}

extension FCL: ASWebAuthenticationPresentationContextProviding {
    public func presentationAnchor(for _: ASWebAuthenticationSession) -> ASPresentationAnchor {
        if let anchor = self.delegate?.presentationAnchor() {
            return anchor
        }
        return ASPresentationAnchor()
    }
}
