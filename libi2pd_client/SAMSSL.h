/*
* Copyright (c) 2013-2025, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef SAMSSL_H__
#define SAMSSL_H__

#include <memory>
#include <string>
#include <thread>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace i2p
{
namespace client
{
	// A lightweight TLS terminator for SAM: accepts TLS and bridges to plaintext SAM
	class SAMSslTerminator
	{
		public:
 
 			SAMSslTerminator (const std::string& listenAddress, uint16_t listenPort,
 				const std::string& backendAddress, uint16_t backendPort,
 				const std::string& certFile, const std::string& keyFile);

 			~SAMSslTerminator ();

 			void Start ();
 			void Stop ();

 		private:
 
 			using ssl_socket_t = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
 
 			void Accept ();
 			template<typename Socket>
 			void HandleAccepted (const boost::system::error_code& ecode, std::shared_ptr<Socket> newSocket);
 			void Handshake (std::shared_ptr<ssl_socket_t> socket);
 			void ConnectBackend (std::shared_ptr<ssl_socket_t> frontend);
 
 			void CreateCertificateIfMissing (const std::string& certFile, const std::string& keyFile);
 
 		private:
 
 			bool m_IsRunning;
 			boost::asio::io_context m_Service;
 			std::unique_ptr<boost::asio::ip::tcp::acceptor> m_Acceptor;
 			boost::asio::ssl::context m_SSLContext;
 			std::unique_ptr<std::thread> m_Thread;
 			boost::asio::ip::tcp::endpoint m_BackendEndpoint;
 			std::string m_CertFile;
 			std::string m_KeyFile;
 		};
}
}

#endif // SAMSSL_H__


