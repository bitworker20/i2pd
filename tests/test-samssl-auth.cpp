#include <cassert>
#include <string>

#include "SAMSSL.h"

int main()
{
	{
		auto result = i2p::client::samssl::AuthorizeHandshakeLine (
			"HELLO VERSION MIN=3.0 MAX=3.3 USER=alice PASSWORD=secret\n",
			true, "alice", "secret");
		assert (result.authenticated);
		assert (result.forwardLine == "HELLO VERSION MIN=3.0 MAX=3.3\n");
	}

	{
		auto result = i2p::client::samssl::AuthorizeHandshakeLine (
			"HELLO VERSION USER=alice PASSWORD=wrong\n",
			true, "alice", "secret");
		assert (!result.authenticated);
		assert (result.forwardLine.empty ());
	}

	{
		auto result = i2p::client::samssl::AuthorizeHandshakeLine (
			"HELLO VERSION MIN=3.0 MAX=3.3\n",
			false, "", "");
		assert (result.authenticated);
		assert (result.forwardLine == "HELLO VERSION MIN=3.0 MAX=3.3\n");
	}

	{
		auto result = i2p::client::samssl::AuthorizeHandshakeLine (
			"HELLO VERSION MIN=3.0 MAX=3.3 USER=\"alice\" PASSWORD=\"sec ret\"\r\n",
			true, "alice", "sec ret");
		assert (result.authenticated);
		assert (result.forwardLine == "HELLO VERSION MIN=3.0 MAX=3.3\r\n");
	}
}
