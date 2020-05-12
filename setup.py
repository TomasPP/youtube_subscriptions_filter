from setuptools import setup


setup(
    name="subscriptions_filter",
    version="1.0.0",
    license="MIT",
    author="Tomas P",
    author_email="ttt@ttt.tt",
    url="...",
    py_modules=["subscriptions_filter"],
    install_requires=["google-api-python-client>=1.8.2,<=2.0.0", "python-dateutil>=2.7.5,<3", "jsonpath-ng>=1.5,<2",
                      "requests>=2.23,<3", "httplib2>=0.17.3,<1"],
    entry_points={"console_scripts": ["subscriptions_filter=subscriptions_filter:main"]},
)
