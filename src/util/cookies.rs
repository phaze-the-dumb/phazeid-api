use std::collections::HashMap;

pub fn parse( cookies: String ) -> HashMap<String, String>{
  let cookies: Vec<&str> = cookies.split("&").collect();
  let mut map: HashMap<String, String> = HashMap::new();

  for cookie in cookies{
    let mut cookie = cookie.split("=");
    map.insert(cookie.nth(0).unwrap().to_owned(), cookie.nth(0).unwrap().to_owned());
  }

  map
}