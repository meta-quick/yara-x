  import "console"
  rule test {
    strings:
      $a = "foobar"
    condition:
      $a and console.log("hello")
  }