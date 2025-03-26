//
//  DomainFronting.swift
//  Rendezvous
//
//  Created by Nora Trapp on 3/26/25.
//

import Foundation

struct DomainFronting {
    /// Common domains that share a CDN with Google
    private static let googleFrontingBaseURLs = [
        URL(string: "https://ww.google.com")!,
        URL(string: "https://android.clients.google.com")!,
        URL(string: "https://clients3.google.com")!,
        URL(string: "https://clients4.google.com")!,
    ]
    
    /**
     Creates a task that retrieves the contents of a URL based on the specified URL request object, and calls a handler upon completion.
     
     This task is setup to covertly route via the `frontingBase`, such that the unencrypted SNI header exposes the fronting domain,
     and the encrypted `Host` header represents the true destination, allowing the CDN to route traffic correctly.
     */
    static func dataTask(
        with request: URLRequest,
        frontingBase: URL,
        completionHandler: @escaping (Data?, URLResponse?, Error?) -> Void
    ) -> URLSessionDataTask {
        let originalUrl = request.url
        var request = request
        request.url = URL(string: originalUrl?.path() ?? "", relativeTo: frontingBase)
        request.setValue(originalUrl?.host(), forHTTPHeaderField: "Host")
        return URLSession.shared.dataTask(with: request, completionHandler: completionHandler)
    }
    
    /// Creates a task specifically fronted via one of multiple common Google fronts, useful for
    /// sites served via Google's CDN.
    static func googleFrontedDataTask(
        with request: URLRequest,
        completionHandler: @escaping (Data?, URLResponse?, Error?) -> Void
    ) -> URLSessionDataTask {
        dataTask(
            with: request,
            frontingBase: googleFrontingBaseURLs.randomElement()!,
            completionHandler: completionHandler
        )
    }
}
