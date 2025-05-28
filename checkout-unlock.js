let body = $response.body;

// 修改金额为非零，防止因金额为0被禁用
body = body.replace(
  /<div class="price-amount amt" id="totalDueToday">.*?<\/div>/,
  `<div class="price-amount amt" id="totalDueToday">¥680.00CNY</div>`
);

// 插入 JS 脚本解除按钮限制，并延迟触发点击事件
body = body.replace(
  /<\/body>/,
  `<script>
    document.addEventListener("DOMContentLoaded", function() {
      var btn = document.getElementById("checkout");
      if (btn) {
        btn.disabled = false;
        btn.classList.remove("disabled");
        btn.removeAttribute("disabled");
        console.log("✅ 已解除按钮禁用");

        // 延迟触发点击事件，确保页面绑定完成
        setTimeout(function() {
          var evt = new MouseEvent("click", {
            bubbles: true,
            cancelable: true,
            view: window
          });
          btn.dispatchEvent(evt);
          console.log("✅ 已触发按钮点击事件");
        }, 500); // 延迟 500 毫秒，可按需调整

        // 同步更新金额显示
        var totalDue = document.getElementById("totalDueToday");
        if (totalDue) {
          totalDue.innerText = "¥680.00CNY";
          console.log("✅ 金额已修改");
        }
      }
    });
  </script></body>`
);

$done({ body });
