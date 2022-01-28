# falcon-casbin [![Build Status](https://travis-ci.com/alexferl/falcon-casbin.svg?branch=master)](https://travis-ci.com/alexferl/falcon-casbin) [![codecov](https://codecov.io/gh/alexferl/falcon-casbin/branch/master/graph/badge.svg)](https://codecov.io/gh/alexferl/falcon-casbin)

A simple [Falcon](https://github.com/falconry/falcon) module for [Casbin](https://casbin.org/) using
[RBAC](https://casbin.org/docs/en/rbac).


## Install
```shell
pip install falcon-casbin
```

## Usage
```python
import falcon
from falcon_casbin import CasbinMiddleware

casbin = CasbinMiddleware("path/to/model.conf", "path/to/policy.csv")

api = falcon.App(middleware=[casbin])
```

## Credits
Inspired by [falcon-policy](https://github.com/falconry/falcon-policy).
