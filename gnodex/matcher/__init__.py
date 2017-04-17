from .service import batch_matcher_service


def setup_argparser(parser):
    parser.set_defaults(func=batch_matcher_service)
