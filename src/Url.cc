// homer::Url v0.3.0
// MIT License
// https://github.com/homer6/url

//#include "sys.h"
#include "Url.h"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace homer6 {

Url::Url(std::string const& s)
{
  fromString(s);
}

unsigned short Url::getPort() const
{
  if (m_port.size() > 0) return std::atoi(m_port.c_str());

  if (m_scheme == "https") return 443;
  if (m_scheme == "http") return 80;
  if (m_scheme == "ssh") return 22;
  if (m_scheme == "ftp") return 21;
  if (m_scheme == "mysql") return 3306;
  if (m_scheme == "mongo") return 27017;
  if (m_scheme == "mongo+srv") return 27017;
  if (m_scheme == "kafka") return 9092;
  if (m_scheme == "postgres") return 5432;
  if (m_scheme == "postgresql") return 5432;
  if (m_scheme == "redis") return 6379;
  if (m_scheme == "zookeeper") return 2181;
  if (m_scheme == "ldap") return 389;
  if (m_scheme == "ldaps") return 636;

  return 0;
}

std::string Url::getPath() const
{
  std::string tmp_path;
  unescape_path(m_path, tmp_path);
  return tmp_path;
}

std::string_view Url::captureUpTo(std::string_view const right_delimiter, std::string const& error_message)
{
  m_right_position = m_parse_target.find_first_of(right_delimiter, m_left_position);

  if (m_right_position == std::string::npos && error_message.size()) { throw std::runtime_error(error_message); }

  std::string_view captured = m_parse_target.substr(m_left_position, m_right_position - m_left_position);

  return captured;
}

bool Url::moveBefore(std::string_view const right_delimiter)
{
  size_t position = m_parse_target.find_first_of(right_delimiter, m_left_position);

  if (position != std::string::npos)
  {
    m_left_position = position;
    return true;
  }

  return false;
}

bool Url::existsForward(std::string_view const right_delimiter)
{
  size_t position = m_parse_target.find_first_of(right_delimiter, m_left_position);

  if (position != std::string::npos) { return true; }

  return false;
}

void Url::fromString(std::string const& source_string)
{
  m_whole_url_storage = source_string;  //copy

  //reset target
  m_parse_target   = m_whole_url_storage;
  m_left_position  = 0;
  m_right_position = 0;

  m_authority_present = false;

  // scheme
  m_scheme = captureUpTo(":", "Expected : in Url");
  std::transform(m_scheme.begin(), m_scheme.end(), m_scheme.begin(), [](std::string_view::value_type c) { return std::tolower(c); });
  m_left_position += m_scheme.size() + 1;

  // authority

  if (moveBefore("//"))
  {
    m_authority_present = true;
    m_left_position += 2;
  }

  if (m_authority_present)
  {
    m_authority = captureUpTo("/");

    bool path_exists = false;

    if (moveBefore("/")) { path_exists = true; }

    if (existsForward("?"))
    {
      m_path = captureUpTo("?");
      moveBefore("?");
      m_left_position++;

      if (existsForward("#"))
      {
        m_query = captureUpTo("#");
        moveBefore("#");
        m_left_position++;
        m_fragment = captureUpTo("#");
      }
      else
      {
        //no fragment
        m_query = captureUpTo("#");
      }
    }
    else
    {
      //no query
      if (existsForward("#"))
      {
        m_path = captureUpTo("#");
        moveBefore("#");
        m_left_position++;
        m_fragment = captureUpTo("#");
      }
      else
      {
        //no fragment
        if (path_exists) { m_path = captureUpTo("#"); }
      }
    }
  }
  else
  {
    m_path = captureUpTo("#");
  }

  //parse authority

  //reset target
  m_parse_target   = m_authority;
  m_left_position  = 0;
  m_right_position = 0;

  if (existsForward("@"))
  {
    m_user_info = captureUpTo("@");
    moveBefore("@");
    m_left_position++;
  }
  else
  {
    //no user_info
  }

  //detect ipv6
  if (existsForward("["))
  {
    m_left_position++;
    m_host = captureUpTo("]", "Malformed ipv6");
    m_left_position++;
    m_ipv6_host = true;
  }
  else
  {
    if (existsForward(":"))
    {
      m_host = captureUpTo(":");
      moveBefore(":");
      m_left_position++;
      m_port = captureUpTo("#");
    }
    else
    {
      //no port
      m_host = captureUpTo(":");
    }
  }

  //parse user_info

  //reset target
  m_parse_target   = m_user_info;
  m_left_position  = 0;
  m_right_position = 0;

  if (existsForward(":"))
  {
    m_username = captureUpTo(":");
    moveBefore(":");
    m_left_position++;

    m_password = captureUpTo("#");
  }
  else
  {
    //no password

    m_username = captureUpTo(":");
  }

  //update secure
  if (m_scheme == "ssh" || m_scheme == "https" || m_port == "443") { m_secure = true; }

  if (m_scheme == "postgres" || m_scheme == "postgresql")
  {
    //reset parse target to query
    m_parse_target   = m_query;
    m_left_position  = 0;
    m_right_position = 0;

    if (existsForward("ssl=true")) { m_secure = true; }
  }
}

bool Url::unescape_path(std::string const& in, std::string& out)
{
  out.clear();
  out.reserve(in.size());

  for (std::size_t i = 0; i < in.size(); ++i)
  {
    switch (in[i])
    {
      case '%':

        if (i + 3 <= in.size())
        {
          unsigned int value = 0;

          for (std::size_t j = i + 1; j < i + 3; ++j)
          {
            switch (in[j])
            {
              case '0':
              case '1':
              case '2':
              case '3':
              case '4':
              case '5':
              case '6':
              case '7':
              case '8':
              case '9':
                value += in[j] - '0';
                break;

              case 'a':
              case 'b':
              case 'c':
              case 'd':
              case 'e':
              case 'f':
                value += in[j] - 'a' + 10;
                break;

              case 'A':
              case 'B':
              case 'C':
              case 'D':
              case 'E':
              case 'F':
                value += in[j] - 'A' + 10;
                break;

              default:
                return false;
            }

            if (j == i + 1) value <<= 4;
          }

          out += static_cast<char>(value);
          i += 2;
        }
        else
        {
          return false;
        }

        break;

      case '-':
      case '_':
      case '.':
      case '!':
      case '~':
      case '*':
      case '\'':
      case '(':
      case ')':
      case ':':
      case '@':
      case '&':
      case '=':
      case '+':
      case '$':
      case ',':
      case '/':
      case ';':
        out += in[i];
        break;

      default:
        if (!std::isalnum(in[i])) return false;
        out += in[i];
        break;
    }
  }

  return true;
}

bool operator==(Url const& a, Url const& b)
{
  return a.m_scheme == b.m_scheme && a.m_username == b.m_username && a.m_password == b.m_password && a.m_host == b.m_host && a.m_port == b.m_port && a.m_path == b.m_path &&
         a.m_query == b.m_query && a.m_fragment == b.m_fragment;
}

bool operator!=(Url const& a, Url const& b)
{
  return !(a == b);
}

bool operator<(Url const& a, Url const& b)
{
  if (a.m_scheme < b.m_scheme) return true;
  if (b.m_scheme < a.m_scheme) return false;

  if (a.m_username < b.m_username) return true;
  if (b.m_username < a.m_username) return false;

  if (a.m_password < b.m_password) return true;
  if (b.m_password < a.m_password) return false;

  if (a.m_host < b.m_host) return true;
  if (b.m_host < a.m_host) return false;

  if (a.m_port < b.m_port) return true;
  if (b.m_port < a.m_port) return false;

  if (a.m_path < b.m_path) return true;
  if (b.m_path < a.m_path) return false;

  if (a.m_query < b.m_query) return true;
  if (b.m_query < a.m_query) return false;

  return a.m_fragment < b.m_fragment;
}

std::string Url::toString() const
{
  return m_whole_url_storage;
}

Url::operator std::string() const
{
  return toString();
}

} // namespace homer6
