//
//  File.swift
//
//
//  Created by lmcmz on 29/8/21.
//

import AsyncHTTPClient
import Combine
import Flow
import Foundation
import NIO
import NIOHTTP1

class API {
    internal let defaultUserAgent = "Flow SWIFT SDK"
    internal var cancellables = Set<AnyCancellable>()

    // TODO: Improve this
    internal var canContinue = true

    func decodeToModel<T: Decodable>(body: ByteBuffer?) -> T? {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase

        do {
            _ = try decoder.decode(T.self, from: body!)
        } catch {
            print(error)
        }

        guard let data = body,
              let model = try? decoder.decode(T.self, from: data) else {
            return nil
        }

        return model
    }
}

func buildURL(url: URL, params: [String: String]?) -> URL? {
    let paramLocation = "l6n"
    guard var urlComponents = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
        return nil
    }

    var queryItems: [URLQueryItem] = []

    if let location = fcl.config.get(key: .location) {
        queryItems.append(URLQueryItem(name: paramLocation, value: location))
    }

    for (name, value) in params ?? [:] {
        if name != paramLocation {
            queryItems.append(
                URLQueryItem(name: name, value: value)
            )
        }
    }

    urlComponents.queryItems = queryItems
    return urlComponents.url
}
