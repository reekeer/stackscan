from stackscan.analyzers.vibe import detect_vibe_code


def test_vibe_code_detects_commented_markup() -> None:
    body = """
<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<!-- Header -->
<header class="bg-gray-100 p-4 rounded-lg flex">
  <h1>Hello</h1>
</header>
<!-- Footer -->
<footer class="text-sm text-gray-500">bye</footer>
</body>
</html>
"""
    hits = detect_vibe_code(body)
    assert any(h.name == "Vibe-coded" for h in hits)


def test_obfuscated_code_is_not_vibe_coded() -> None:
    body = "<script>var a,b,c,d,e; eval(atob('YWxlcnQoMSk='));</script>"
    assert detect_vibe_code(body) == []


def test_emojis_increase_confidence() -> None:
    body = """<!DOCTYPE html><html><head><title>X</title></head><body>
    <!-- Hero -->
    <div class="p-4 rounded bg-white">
      <h1>🚀 ✨ 🔥 Hello world</h1>
      <p>This is a demo paragraph with enough content to pass the minimum length check.</p>
      <p>More text here so the body is longer than two hundred characters.</p>
    </div>
    </body></html>"""
    hits = detect_vibe_code(body)
    assert any(h.name == "Vibe-coded" for h in hits)
