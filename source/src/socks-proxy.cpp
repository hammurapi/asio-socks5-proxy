/**
 * @file boost_socks5.cpp
 * @brief Simple SOCKS5 proxy server realization using asio library
 * @author philave (philave7@gmail.com)
 * @author hammurapi (https://github.com/hammurapi)
 */

#include <asio.hpp>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <utility>

#include <spdlog/spdlog.h>

#include "config-reader.hpp"
#include "version.h"

using asio::ip::tcp;

class Session : public std::enable_shared_from_this<Session> {
  public:
	Session( tcp::socket in_socket, unsigned session_id, size_t buffer_size )
		: in_socket_( std::move( in_socket ) ),
		  out_socket_( in_socket.get_executor() ),
		  resolver( in_socket.get_executor() ),
		  in_buf_( buffer_size ),
		  out_buf_( buffer_size ),
		  session_id_( session_id ) {
	}

	void start() {
		read_socks5_handshake();
	}

  private:
	void read_socks5_handshake() {
		auto self( shared_from_this() );

		in_socket_.async_receive( asio::buffer( in_buf_ ),
								  [this, self]( std::error_code ec, std::size_t length ) {
									  if( !ec ) {
										  /*
													  The client connects to the server, and sends a version
													  identifier/method selection message:

													  +----+----------+----------+
													  |VER | NMETHODS | METHODS  |
													  +----+----------+----------+
													  | 1  |    1     | 1 to 255 |
													  +----+----------+----------+

													  The values currently defined for METHOD are:

													  o  X'00' NO AUTHENTICATION REQUIRED
													  o  X'01' GSSAPI
													  o  X'02' USERNAME/PASSWORD
													  o  X'03' to X'7F' IANA ASSIGNED
													  o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
													  o  X'FF' NO ACCEPTABLE METHODS

													  */
										  if( length < 3 || in_buf_[0] != 0x05 ) {
											  // write_log( 1, 0, verbose_, session_id_, "SOCKS5 handshake request is invalid. Closing session." );
											  spdlog::error( "(session: {0}) SOCKS5 handshake request is invalid. Closing session.", session_id_ );
											  return;
										  }

										  uint8_t num_methods = in_buf_[1];
										  // Prepare request
										  in_buf_[1] = 0xFF;

										  // Only 0x00 - 'NO AUTHENTICATION REQUIRED' is now support_ed
										  for( uint8_t method = 0; method < num_methods; ++method )
											  if( in_buf_[2 + method] == 0x00 ) {
												  in_buf_[1] = 0x00;
												  break;
											  }

										  write_socks5_handshake();
									  } else {
										  // write_log( 1, 0, verbose_, session_id_, "SOCKS5 handshake request", ec.message() );
										  spdlog::error( "(session: {0}) SOCKS5 handshake request {1}", session_id_, ec.message() );
									  }
								  } );
	}

	void write_socks5_handshake() {
		auto self( shared_from_this() );

		asio::async_write( in_socket_, asio::buffer( in_buf_, 2 ), // Always 2-byte according to RFC1928
						   [this, self]( std::error_code ec, std::size_t length ) {
							   if( !ec ) {
								   if( in_buf_[1] == (char) 0xFF )
									   return; // No appropriate auth method found. Close session.
								   read_socks5_request();
							   } else {
								   // write_log( 1, 0, verbose_, session_id_, "SOCKS5 handshake response write", ec.message() );

								   spdlog::error( "(session: {0}) SOCKS5 handshake response write {1}", session_id_, ec.message() );
							   }
						   } );
	}

	void read_socks5_request() {
		auto self( shared_from_this() );

		in_socket_.async_receive( asio::buffer( in_buf_ ),
								  [this, self]( std::error_code ec, std::size_t length ) {
									  if( !ec ) {
										  /*
													  The SOCKS request is formed as follows:

													  +----+-----+-------+------+----------+----------+
													  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
													  +----+-----+-------+------+----------+----------+
													  | 1  |  1  | X'00' |  1   | Variable |    2     |
													  +----+-----+-------+------+----------+----------+

													  Where:

													  o  VER    protocol version: X'05'
													  o  CMD
													  o  CONNECT X'01'
													  o  BIND X'02'
													  o  UDP ASSOCIATE X'03'
													  o  RSV    RESERVED
													  o  ATYP   address type of following address
													  o  IP V4 address: X'01'
													  o  DOMAINNAME: X'03'
													  o  IP V6 address: X'04'
													  o  DST.ADDR       desired destination address
													  o  DST.PORT desired destination port_ in network octet
													  order

													  The SOCKS server will typically evaluate the request based on source
													  and destination addresses, and return one or more reply messages, as
													  appropriate for the request type.
													  */
										  if( length < 5 || in_buf_[0] != 0x05 || in_buf_[1] != 0x01 ) {
											  //  write_log( 1, 0, verbose_, session_id_, "SOCKS5 request is invalid. Closing session." );

											  spdlog::error( "(session: {0}) SOCKS5 request is invalid. Closing session.", session_id_ );
											  return;
										  }

										  uint8_t addr_type = in_buf_[3], host_length;

										  switch( addr_type ) {
											  case 0x01: // IP V4 address
												  if( length != 10 ) {
													  // write_log( 1, 0, verbose_, session_id_, "SOCKS5 request length is invalid. Closing session." );
													  spdlog::error( "(session: {0}) SOCKS5 request length is invalid. Closing session.", session_id_ );
													  return;
												  }
												  remote_host_ = asio::ip::address_v4( ntohl( *( (uint32_t*) &in_buf_[4] ) ) ).to_string();
												  remote_port_ = std::to_string( ntohs( *( (uint16_t*) &in_buf_[8] ) ) );
												  break;
											  case 0x03: // DOMAINNAME
												  host_length = in_buf_[4];
												  if( length != (size_t) ( 5 + host_length + 2 ) ) {
													  // write_log( 1, 0, verbose_, session_id_, "SOCKS5 request length is invalid. Closing session." );
													  spdlog::error( "(session: {0}) SOCKS5 request length is invalid. Closing session.", session_id_ );
													  return;
												  }
												  remote_host_ = std::string( &in_buf_[5], host_length );
												  remote_port_ = std::to_string( ntohs( *( (uint16_t*) &in_buf_[5 + host_length] ) ) );
												  break;
											  case 0x04: // IP V6 address
												  if( length != 22 ) {
													  // write_log( 1, 0, verbose_, session_id_, "SOCKS5 request length is invalid. Closing session." );
													  spdlog::error( "(session: {0}) SOCKS5 request length is invalid. Closing session.", session_id_ );
													  return;
												  }

												  remote_host_ = asio::ip::address_v6( *reinterpret_cast<asio::ip::address_v6::bytes_type*>( &in_buf_[4] ) ).to_string();
												  // remote_host_ = asio::ip::address_v4( ntohl( *( (uint32_t*) &in_buf_[4] ) ) ).to_string();
												  remote_port_ = std::to_string( ntohs( *( (uint16_t*) &in_buf_[20] ) ) );
												  break;
											  default:
												  // write_log( 1, 0, verbose_, session_id_, "unsupport_ed address type in SOCKS5 request. Closing session." );

												  spdlog::error( "(session: {0}) unsupported address type in SOCKS5 request (addr_type={1}). Closing session.", session_id_, addr_type );
												  break;
										  }

										  do_resolve();
									  } else {
										  // write_log( 1, 0, verbose_, session_id_, "SOCKS5 request read", ec.message() );
										  spdlog::error( "(session: {0}) SOCKS5 request read {1}", session_id_, ec.message() );
									  }
								  } );
	}

	void do_resolve() {
		auto self( shared_from_this() );

		resolver.async_resolve( remote_host_, remote_port_,
								[this, self]( const std::error_code& ec, const tcp::resolver::results_type& endpoints ) {
									if( !ec ) {
										do_connect( endpoints );
									} else {
										// std::ostringstream what;
										// what << "failed to resolve " << remote_host_ << ":" << remote_port_;
										// write_log( 1, 0, verbose_, session_id_, what.str(), ec.message() );

										spdlog::error( "(session: {0}) failed to resolve {1}:{2} : {3}", session_id_, remote_host_, remote_port_, ec.message() );
									}
								} );
	}

	void do_connect( const tcp::resolver::results_type& endpoints ) {
		auto self( shared_from_this() );
		asio::async_connect( out_socket_, endpoints,
							 [this, self]( const std::error_code& ec, const tcp::endpoint& endpoint ) {
								 if( !ec ) {
									 // std::ostringstream what;
									 // what << "connected to " << remote_host_ << ":" << remote_port_;
									 // write_log( 0, 1, verbose_, session_id_, what.str() );

									 spdlog::info( "(session: {0}) connected to {1}:{2}", session_id_, remote_host_, remote_port_ );
									 write_socks5_response();
								 } else {
									 // std::ostringstream what;
									 // what << "failed to connect " << remote_host_ << ":" << remote_port_;
									 // write_log( 1, 0, verbose_, session_id_, what.str(), ec.message() );
									 spdlog::error( "(session: {0}) failed to connect {1}:{2} : {3}", session_id_, remote_host_, remote_port_, ec.message() );
								 }
							 } );
	}

	void write_socks5_response() {
		auto self( shared_from_this() );

		/*
		The SOCKS request information is sent by the client as soon as it has
		established a connection to the SOCKS server, and completed the
		authentication negotiations.  The server evaluates the request, and
		returns a reply formed as follows:

		+----+-----+-------+------+----------+----------+
		|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		+----+-----+-------+------+----------+----------+
		| 1  |  1  | X'00' |  1   | Variable |    2     |
		+----+-----+-------+------+----------+----------+

		Where:

		o  VER    protocol version: X'05'
		o  REP    Reply field:
		o  X'00' succeeded
		o  X'01' general SOCKS server failure
		o  X'02' connection not allowed by ruleset
		o  X'03' Network unreachable
		o  X'04' Host unreachable
		o  X'05' Connection refused
		o  X'06' TTL expired
		o  X'07' Command not support_ed
		o  X'08' Address type not support_ed
		o  X'09' to X'FF' unassigned
		o  RSV    RESERVED
		o  ATYP   address type of following address
		o  IP V4 address: X'01'
		o  DOMAINNAME: X'03'
		o  IP V6 address: X'04'
		o  BND.ADDR       server bound address
		o  BND.PORT       server bound port_ in network octet order

		Fields marked RESERVED (RSV) must be set to X'00'.
		*/

		size_t length;
		
		in_buf_[0] = 0x05;
		in_buf_[1] = 0x00;
		in_buf_[2] = 0x00;
		if( out_socket_.remote_endpoint().protocol() == asio::ip::tcp::v4() ) {
			in_buf_[3] = 0x01;		// IP V4 address: X'01'

			uint32_t realRemoteIP = htonl( out_socket_.remote_endpoint().address().to_v4().to_uint() );
			uint16_t realRemoteport = htons( out_socket_.remote_endpoint().port() );

			std::memcpy( &in_buf_[4], &realRemoteIP, 4 );
			std::memcpy( &in_buf_[8], &realRemoteport, 2 );

			length = 10;
		} else if( out_socket_.remote_endpoint().protocol() == asio::ip::tcp::v6() ) {
			in_buf_[3] = 0x04; // IP V6 address: X'04'

			auto realRemoteIP = out_socket_.remote_endpoint().address().to_v6().to_bytes();			
			uint16_t realRemoteport = htons( out_socket_.remote_endpoint().port() );

			std::memcpy( &in_buf_[4], &realRemoteIP, 16 );
			std::memcpy( &in_buf_[20], &realRemoteport, 2 );

			length = 22;
		} else {
			// write_log( 1, 0, verbose_, session_id_, "unsupported address type in SOCKS5 request. Closing session." );

			spdlog::error( "(session: {0}) unsupported protocol type in SOCKS5 request (protocol={1}). Closing session.", session_id_, out_socket_.remote_endpoint().protocol().type() );
			return;
		}

		asio::async_write( in_socket_, asio::buffer( in_buf_, length ), // Always 10-byte according to RFC1928
						   [this, self]( std::error_code ec, std::size_t length ) {
							   if( !ec ) {
								   do_read( 3 ); // Read both sockets
							   } else
								   // write_log( 1, 0, verbose_, session_id_, "SOCKS5 response write", ec.message() );
								   spdlog::error( "(session: {0}) SOCKS5 response write {1}", session_id_, ec.message() );
						   } );
	}

	void do_read( int direction ) {
		auto self( shared_from_this() );

		// We must divide reads by direction to not permit second read call on the same socket.
		if( direction & 0x1 )
			in_socket_.async_receive( asio::buffer( in_buf_ ),
									  [this, self]( std::error_code ec, std::size_t length ) {
										  if( !ec ) {
											  // std::ostringstream what;
											  // what << "--> " << std::to_string( length ) << " bytes";
											  // write_log( 0, 2, verbose_, session_id_, what.str() );
											  spdlog::debug( "(session: {0}) --> {1} bytes", session_id_, length );

											  do_write( 1, length );
										  } else // if (ec != asio::error::eof)
										  {
											  if( ec == asio::error::eof ) {
												  spdlog::info( "(session: {0}) closing session. Client socket read error {1}", session_id_, ec.message() );
											  } else {
												  // write_log( 2, 1, verbose_, session_id_, "closing session. Client socket read error", ec.message() );
												  spdlog::warn( "(session: {0}) closing session. Client socket read error {1}", session_id_, ec.message() );
											  }

											  // Most probably client closed socket. Let's close both sockets and exit session.
											  in_socket_.close();
											  out_socket_.close();
										  }
									  } );

		if( direction & 0x2 )
			out_socket_.async_receive( asio::buffer( out_buf_ ),
									   [this, self]( std::error_code ec, std::size_t length ) {
										   if( !ec ) {
											   // std::ostringstream what;
											   // what << "<-- " << std::to_string( length ) << " bytes";
											   //  write_log( 0, 2, verbose_, session_id_, what.str() );
											   spdlog::debug( "(session: {0}) <-- {1} bytes", session_id_, length );

											   do_write( 2, length );
										   } else // if (ec != asio::error::eof)
										   {
											   if( ec == asio::error::eof ) {
												   spdlog::info( "(session: {0}) closing session. Remote socket read error {1}", session_id_, ec.message() );
											   } else {
												   spdlog::warn( "(session: {0}) closing session. Remote socket read error {1}", session_id_, ec.message() );
											   }
											   // write_log( 2, 1, verbose_, session_id_, "closing session. Remote socket read error", ec.message() );

											   // Most probably remote server closed socket. Let's close both sockets and exit session.
											   in_socket_.close();
											   out_socket_.close();
										   }
									   } );
	}

	void do_write( int direction, std::size_t Length ) {
		auto self( shared_from_this() );

		switch( direction ) {
			case 1:
				asio::async_write( out_socket_, asio::buffer( in_buf_, Length ),
								   [this, self, direction]( std::error_code ec, std::size_t length ) {
									   if( !ec )
										   do_read( direction );
									   else {
										   if( ec == asio::error::eof ) {
											   spdlog::info( "(session: {0}) closing session. Client socket write error {1}", session_id_, ec.message() );
										   } else {
											   spdlog::warn( "(session: {0}) closing session. Client socket write error {1}", session_id_, ec.message() );
										   }
										   // write_log( 2, 1, verbose_, session_id_, "closing session. Client socket write error", ec.message() );

										   // Most probably client closed socket. Let's close both sockets and exit session.
										   in_socket_.close();
										   out_socket_.close();
									   }
								   } );
				break;
			case 2:
				asio::async_write( in_socket_, asio::buffer( out_buf_, Length ),
								   [this, self, direction]( std::error_code ec, std::size_t length ) {
									   if( !ec )
										   do_read( direction );
									   else {
										   spdlog::warn( "(session: {0}) closing session. Remote socket write error {1}", session_id_, ec.message() );
										   // write_log( 2, 1, verbose_, session_id_, "closing session. Remote socket write error", ec.message() );

										   // Most probably remote server closed socket. Let's close both sockets and exit session.
										   in_socket_.close();
										   out_socket_.close();
									   }
								   } );
				break;
		}
	}

	tcp::socket in_socket_;
	tcp::socket out_socket_;
	tcp::resolver resolver;

	std::string remote_host_;
	std::string remote_port_;
	std::vector<char> in_buf_;
	std::vector<char> out_buf_;
	int session_id_;
};

class Server {
  public:
	Server( asio::io_context& io_context, short port, unsigned buffer_size )
		: acceptor_( io_context, tcp::endpoint( tcp::v4(), port ) ),
		  in_socket_( io_context ), buffer_size_( buffer_size ), session_id_( 0 ) {
		spdlog::info( "accepting connections on {}:{}",
					  acceptor_.local_endpoint().address().to_string(),
					  acceptor_.local_endpoint().port() );

		do_accept();
	}

  private:
	void do_accept() {
		acceptor_.async_accept( in_socket_,
								[this]( std::error_code ec ) {
									if( !ec ) {
										std::make_shared<Session>( std::move( in_socket_ ), session_id_++, buffer_size_ )->start();
									} else
										// write_log( 1, 0, verbose_, session_id_, "socket accept error", ec.message() );
										spdlog::error( "(session: {0}) socket accept error {1}", session_id_, ec.message() );

									do_accept();
								} );
	}

	tcp::acceptor acceptor_;
	tcp::socket in_socket_;
	size_t buffer_size_;
	unsigned session_id_;
};

std::string extract_file_name( const std::string& the_path ) {
	std::filesystem::path path( the_path );

	return path.filename().string();
}

int main( int argc, char* argv[] ) {
	std::string executable_file_name = extract_file_name( argv[0] );
	spdlog::info( "###########################################################################################" );
	spdlog::info( "##########  {0} STARTED  ##########  VERSION {1}", executable_file_name, VER_FILEVERSION_STR );
	spdlog::info( "###########################################################################################" );

	// std::cout << argv[0] << " " << VER_FILEVERSION_STR << std::endl;

	// short verbose = 0;
	try {
		if( argc != 2 ) {
			std::cout << "Usage: " << executable_file_name << " <config_file>" << std::endl;
			return 1;
		}

		ConfigReader conf;
		conf.parse( argv[1] );

		short port = conf.check_key( "port" ) ? std::atoi( conf.get_key_value( "port" ) ) : 1080;						// Default port_
		size_t buffer_size = conf.check_key( "buffer_size" ) ? std::atoi( conf.get_key_value( "buffer_size" ) ) : 8192; // Default buffer_size
		// verbose = conf.check_key( "verbose" ) ? std::atoi( conf.get_key_value( "verbose" ) ) : 0;						// Default verbose_
		auto log_level = conf.check_key( "log_level" ) ? spdlog::level::from_str( conf.get_key_value( "log_level" ) ) : spdlog::level::info;

		spdlog::set_level( log_level );

		asio::io_context io_context;
		Server server( io_context, port, buffer_size );
		io_context.run();
	} catch( std::exception& e ) {
		spdlog::critical( "Exception caught in {0}: {1}", __FUNCTION__, e.what() );
		// write_log( 1, 0, verbose, -1, "", e.what() );
	} catch( ... ) {
		spdlog::critical( "Exception caught in {0}: ...", __FUNCTION__ );
	}

	spdlog::shutdown();

	return 0;
}
