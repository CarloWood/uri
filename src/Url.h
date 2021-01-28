// homer::Url v0.3.0
// MIT License
// https://github.com/homer6/url

// This class takes inspiration and some source code from
// https://github.com/chriskohlhoff/urdl/blob/master/include/urdl/url.hpp

#pragma once

#include <map>
#include <string>
#include <string_view>

namespace homer6 {

//  Url and UrlView are compliant with
//      https://tools.ietf.org/html/rfc3986
//      https://tools.ietf.org/html/rfc6874
//      https://tools.ietf.org/html/rfc7320
//      and adheres to https://rosettacode.org/wiki/URL_parser examples.
//
//  Url will use default ports for known schemes, if the port is not explicitly provided.
//

class Url
{
 public:
  Url();
  Url(std::string const& s);

  std::string getScheme() const { return m_scheme; }
  std::string getUsername() const { return m_username; }
  std::string getPassword() const { return m_password; }
  std::string getHost() const { return m_host; }
  std::string getQuery() const { return m_query; }
  std::multimap<std::string, std::string> const& getQueryParameters() const { return m_query_parameters; }
  std::string getFragment() const { return m_fragment; }
  bool isIpv6() const { return m_ipv6_host; }
  bool isSecure() const { return m_secure; }

  void setSecure(bool secure) { m_secure = secure; }

  unsigned short getPort() const;
  std::string getPath() const;

  void fromString(std::string const& s);

  friend bool operator==(Url const& a, Url const& b);
  friend bool operator!=(Url const& a, Url const& b);
  friend bool operator<(Url const& a, Url const& b);

  std::string toString() const;
  explicit operator std::string() const;

 protected:
  static bool unescape_path(std::string const& in, std::string& out);

  std::string_view captureUpTo(std::string_view const right_delimiter, std::string const& error_message = "");
  bool moveBefore(std::string_view const right_delimiter);
  bool existsForward(std::string_view const right_delimiter);

  std::string m_scheme;
  std::string m_authority;
  std::string m_user_info;
  std::string m_username;
  std::string m_password;
  std::string m_host;
  std::string m_port;
  std::string m_path;
  std::string m_query;
  std::multimap<std::string, std::string> m_query_parameters;
  std::string m_fragment;

  bool m_secure            = false;
  bool m_ipv6_host         = false;
  bool m_authority_present = false;

  std::string m_whole_url_storage;
  size_t m_left_position  = 0;
  size_t m_right_position = 0;
  std::string_view m_parse_target;
};

}  // namespace homer6
