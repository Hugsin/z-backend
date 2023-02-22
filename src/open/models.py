from django.db import models
from application import dispatch
from src.utils.models import CoreModel, table_prefix


class Projects(CoreModel):
    name = models.CharField(max_length=100, verbose_name='名称')
    desc = models.CharField(max_length=2000, verbose_name='描述')
    image = models.CharField(max_length=200, verbose_name='图片地址')
    order_num = models.IntegerField(
        default=1, verbose_name="显示排序", null=True, blank=True, help_text="显示排序")
    url = models.CharField(
        max_length=2000, verbose_name='链接', help_text="岗位状态")
    STATUS_CHOICES = (
        (0, "网站"),
        (1, "图片"),
        (2, "小程序"),
        (2, "公众号"),
    )
    type = models.IntegerField(
        choices=STATUS_CHOICES, default=1, verbose_name="岗位状态", help_text="岗位状态")

    class Meta:
        db_table = table_prefix + "projects"
        verbose_name = "项目表"
        verbose_name_plural = verbose_name
        ordering = ("order_num",)


class PayOrder(CoreModel):
    TRADE_TYPE_CHOICES = (
        ('JSAPI', "公众号支付"),
        ('NATIVE', "扫码支付"),
        ('APP', "APP支付"),
        ('MICROPAY', "付款码支付"),
        ('MWEB', "H5支付"),
        ('FACEPAY', "刷脸支付"),
    )
    TRADE_STATE_CHOICES = (
        ('SUCCESS', "支付成功"),
        ('REFUND', "转入退款"),
        ('NOTPAY', "未支付"),
        ('CLOSED', "已关闭"),
        ('REVOKED', "已撤销（付款码支付）"),
        ('USERPAYING', "用户支付中（付款码支付）"),
        ('PAYERROR', "支付失败(其他原因，如银行返回失败)"),
    )
    appid = models.CharField(max_length=50, verbose_name='应用ID')
    mchid = models.CharField(max_length=50, verbose_name='商户号')
    out_trade_no = models.CharField(
        max_length=50, db_index=True, verbose_name='商户订单号')
    transaction_id = models.CharField(
        max_length=50, db_index=True, verbose_name='微信支付订单号')
    trade_type = models.CharField(
        choices=TRADE_TYPE_CHOICES, default='NATIVE', max_length=10, verbose_name="交易类型", help_text="交易类型")
    trade_state = models.CharField(
        choices=TRADE_STATE_CHOICES, default='CLOSED', max_length=10, verbose_name="交易状态", help_text="交易状态")
    trade_state_desc = models.CharField(max_length=300, verbose_name='交易状态描述')
    bank_type = models.CharField(max_length=50, verbose_name='付款银行')
    attach = models.CharField(max_length=200, verbose_name='附加数据')
    success_time = models.CharField(max_length=100, verbose_name='支付完成时间')
    payer = models.CharField(max_length=200, verbose_name='支付者信息')
    total = models.IntegerField(
        default=0, verbose_name="总金额", null=True, blank=True, help_text="订单总金额，单位为分")
    currency = models.CharField(max_length=20, verbose_name='人民币，境内商户号仅支持人民币。')

    class Meta:
        db_table = table_prefix + "order"
        verbose_name = "订单表"
        verbose_name_plural = verbose_name
        ordering = ("-success_time",)

class MpKeywordsReply(CoreModel):
    MSG_TYPE_CHOICES = (
        ('text', "文本消息"),
        ('image', "图片消息"),
        ('voice', "语音消息"),
        ('video', "视频消息"),
        ('music', "音乐消息"),
        ('news', "图文消息"),
    )
    msg_type = models.CharField(
        max_length=10, verbose_name='消息类型', help_text='消息类型')
    keyword = models.CharField(
        max_length=100, verbose_name='关键字', help_text='关键字')
    content = models.CharField(
        max_length=2000,
        blank=True,
        null=True,
        verbose_name='回复的消息内容',
        help_text='回复的消息内容（换行：在 content 中能够换行，微信客户端就支持换行显示）')
    media_id = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name='媒体id',
        help_text='通过素材管理中的接口上传多媒体文件，得到的id'
    )
    title = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name='消息的标题',
        help_text='消息的标题')
    description = models.CharField(
        max_length=500,
        blank=True,
        null=True,
        verbose_name='消息的描述',
        help_text='消息的描述')
    music_url = models.CharField(
        max_length=500,
        blank=True,
        null=True,
        verbose_name='音乐链接',
        help_text='音乐链接')
    hq_music_url = models.CharField(
        max_length=500,
        blank=True,
        null=True,
        verbose_name='音乐链接',
        help_text='高质量音乐链接，WIFI环境优先使用该链接播放音乐')
    thumb_media_id = models.CharField(
        max_length=500,
        blank=True,
        null=True,
        verbose_name='缩略图',
        help_text='缩略图的媒体id，通过素材管理中的接口上传多媒体文件，得到的id')
   

    class Meta:
        db_table = table_prefix + "reply"
        verbose_name = "回复关键字表"
        verbose_name_plural = verbose_name
