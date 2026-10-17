import unittest
from unittest.mock import Mock

from scanner.crawler import MAX_PAGES, detect_auth_state, normalize_crawl_url


class FakeLocator:
    def __init__(self, *, attributes=None, text='', count=0, children=None):
        self.attributes = attributes or {}
        self.text = text
        self._count = count
        self.children = children or []

    def all(self):
        return self.children

    def count(self):
        return self._count

    def get_attribute(self, name):
        return self.attributes.get(name)

    def inner_text(self, timeout=None):
        return self.text

    def locator(self, selector):
        return FakeLocator(children=self.children)


class AuthCrawlerTests(unittest.TestCase):
    def page(self, *, url='https://example.com/', password=False, form_text='', body='', controls=''):
        form = FakeLocator(
            text=form_text,
            children=[FakeLocator(attributes={'name': 'username'}, count=1)] if password else [],
        )
        page = Mock()
        page.locator.side_effect = lambda selector: {
            'form': FakeLocator(children=[form]),
            'input[type="password"]': FakeLocator(count=1 if password else 0),
            'body': FakeLocator(text=body),
            'button, input[type="submit"], [role="button"]': FakeLocator(
                children=[FakeLocator(text=controls, count=1)] if controls else []
            ),
        }.get(selector, FakeLocator())
        page.url = url
        return page

    def test_public_page_does_not_request_authentication(self):
        state = detect_auth_state(self.page(body='Welcome to the site'), 'https://example.com/')
        self.assertFalse(state['login_detected'])
        self.assertFalse(state['mfa_detected'])

    def test_username_password_form_requests_authentication(self):
        state = detect_auth_state(self.page(password=True, form_text='Sign in'), 'https://example.com/account')
        self.assertTrue(state['login_detected'])

    def test_mfa_is_flagged_without_bypass(self):
        state = detect_auth_state(self.page(body='Enter your one-time password'), 'https://example.com/verify')
        self.assertTrue(state['mfa_detected'])

    def test_url_normalization_removes_fragments_and_trailing_slash(self):
        self.assertEqual(normalize_crawl_url('HTTPS://Example.com/account/#private'), 'https://example.com/account')

    def test_page_limit_is_100(self):
        self.assertEqual(MAX_PAGES, 100)


if __name__ == '__main__':
    unittest.main()