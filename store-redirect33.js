let body = $response.body;

body = body.replace(
  /<\/body>/,
  `<script>
    document.addEventListener("DOMContentLoaded", function () {
  let win = window.open("about:blank", "_blank");
  win.location.href = "https://app.kaze.network/cart.php?a=checkout";
});

  </script></body>`
);

$done({ body });
