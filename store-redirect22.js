let body = $response.body;

body = body.replace(
  /<\/body>/,
  `<script>
    document.addEventListener("DOMContentLoaded", function () {
    // 找到目标 <li> 内的 <a>
    let cartLink = document.querySelector('li[menuitemname="View Cart"] a');

    if (cartLink) {
        // 创建一个新的 <a> 元素用于在新窗口打开
        let newWinLink = document.createElement("a");
        newWinLink.href = cartLink.href;  // 原链接
        newWinLink.target = "_blank";     // 新窗口打开
        document.body.appendChild(newWinLink);

        // 模拟点击
        newWinLink.click();

        console.log("🧭 已自动在新窗口打开购物车页面");
    } else {
        console.log("⚠️ 未找到 'View Cart' 链接");
    }
});

  // 模拟用户点击
  btn.click();
});

  </script></body>`
);

$done({ body });
