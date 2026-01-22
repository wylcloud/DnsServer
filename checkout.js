let body = $response.body;

/*
 * 1️⃣ 强制修改结账金额（防止金额为 0 被禁用）
 */
body = body.replace(
  /<div class="price-amount amt" id="totalDueToday">[\s\S]*?<\/div>/,
  `<div class="price-amount amt" id="totalDueToday">¥680.00CNY</div>`
);

/*
 * 2️⃣ 注入 JS：监听勾选 → 自动点击结账
 */
body = body.replace(
  /<\/body>/,
  `<script>
    (function () {
      function enableCheckout() {
        var btn = document.getElementById("checkout");
        if (!btn) return;

        btn.disabled = false;
        btn.classList.remove("disabled");
        btn.removeAttribute("disabled");
        console.log("✅ checkout 按钮已解禁");
      }

      function clickCheckout() {
        var btn = document.getElementById("checkout");
        if (!btn) return;

        enableCheckout();

        var evt = new MouseEvent("click", {
          bubbles: true,
          cancelable: true,
          view: window
        });
        btn.dispatchEvent(evt);
        console.log("✅ 已自动点击结账");
      }

      function fixAmount() {
        var total = document.getElementById("totalDueToday");
        if (total) {
          total.innerText = "¥680.00CNY";
          console.log("✅ 已修正结账金额");
        }
      }

      function watchTerms() {
        var terms = document.querySelector('input[type="checkbox"]');
        if (!terms) return;

        // 如果一开始就已经勾选
        if (terms.checked) {
          console.log("✅ 条款已勾选，直接结账");
          clickCheckout();
          return;
        }

        // 监听勾选变化
        terms.addEventListener("change", function () {
          if (terms.checked) {
            console.log("✅ 监听到条款被勾选");
            clickCheckout();
          }
        });
      }

      document.addEventListener("DOMContentLoaded", function () {
        fixAmount();
        enableCheckout();
        watchTerms();
      });
    })();
  </script></body>`
);

$done({ body });
