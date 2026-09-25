"""顶层 `aleth` 转发包 —— grpcio-tools 生成的 pb2_grpc 以 proto package
（aleth.v1）为顶层 import（`from aleth.v1 import aletheia_pb2`），
而仓库的手写代码统一走 `aletheia.gen.aleth.v1`。这里的 re-export 让
两条导入路径解析到**同一个模块对象**（protobuf 类的单一注册表），
避免同一 .proto 生成两份消息类。I0 遗留结构问题的最小修复。"""

from aletheia.gen import aleth  # noqa: F401
