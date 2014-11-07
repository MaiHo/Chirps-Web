$(document).ready(function () {
    $('#schoolsAndCategories').find('input:checkbox').on('click', function () {
        $('#accordion > div').hide();
        $('#schoolsAndCategories').find('input:checked').each(function () {
            $('#accordion > div.' + $(this).attr('value')).show();
        });
    });
});  